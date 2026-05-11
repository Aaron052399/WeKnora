// Package wechatkf implements the WeChat Customer Service (微信客服) IM adapter for WeKnora.
//
// WeChat KF flow:
// 1. External user sends a message to the KF account
// 2. WeCom calls our callback URL with the encrypted message
// 3. We decrypt, parse, and send a reply via the KF send_msg API
//
// Reference: https://developer.work.weixin.qq.com/document/path/94681
package wechatkf

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Tencent/WeKnora/internal/im"
	"github.com/Tencent/WeKnora/internal/logger"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/gin-gonic/gin"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

const defaultAPIBaseURL = "https://qyapi.weixin.qq.com"

// Adapter implements im.Adapter for WeChat Customer Service in webhook mode.
type Adapter struct {
	corpID           string
	kfSecret         string
	openKFID         string
	token            string
	encodingAESKey   string
	aesKey           []byte
	apiBaseURL       string
	extraAllowedHost string

	tokenMu    sync.Mutex
	tokenCache string
	tokenExpAt time.Time
}

// Compile-time checks.
var (
	_ im.Adapter        = (*Adapter)(nil)
	_ im.FileDownloader = (*Adapter)(nil)
)

// NewAdapter creates a new WeChat KF adapter.
func NewAdapter(corpID, kfSecret, openKFID, token, encodingAESKey, apiBaseURL string) (*Adapter, error) {
	aesKey, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, fmt.Errorf("decode encoding_aes_key: %w", err)
	}

	if apiBaseURL == "" {
		apiBaseURL = defaultAPIBaseURL
	}
	apiBaseURL = strings.TrimRight(apiBaseURL, "/")

	if err := validateEndpointURL(apiBaseURL, defaultAPIBaseURL, "https"); err != nil {
		return nil, fmt.Errorf("invalid api_base_url: %w", err)
	}

	return &Adapter{
		corpID:           corpID,
		kfSecret:         kfSecret,
		openKFID:         openKFID,
		token:            token,
		encodingAESKey:   encodingAESKey,
		aesKey:           aesKey,
		apiBaseURL:       apiBaseURL,
		extraAllowedHost: extraHostFromEndpoint(apiBaseURL, defaultAPIBaseURL),
	}, nil
}

func (a *Adapter) Platform() im.Platform {
	return im.PlatformWechatKF
}

// VerifyCallback verifies the WeChat KF callback signature.
func (a *Adapter) VerifyCallback(c *gin.Context) error {
	timestamp := c.Query("timestamp")
	nonce := c.Query("nonce")
	msgSignature := c.Query("msg_signature")

	var encrypt string
	if c.Request.Method == http.MethodGet {
		encrypt = c.Query("echostr")
	} else {
		var body callbackRequestBody
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return fmt.Errorf("read request body: %w", err)
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		if err := xml.Unmarshal(bodyBytes, &body); err != nil {
			return fmt.Errorf("unmarshal xml body: %w", err)
		}
		encrypt = body.Encrypt
	}

	if !a.verifySignature(msgSignature, timestamp, nonce, encrypt) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

// HandleURLVerification handles the WeChat KF URL verification (GET request).
func (a *Adapter) HandleURLVerification(c *gin.Context) bool {
	if c.Request.Method != http.MethodGet {
		return false
	}
	echoStr := c.Query("echostr")
	if echoStr == "" {
		return false
	}
	decrypted, err := a.decrypt(echoStr)
	if err != nil {
		logger.Errorf(c.Request.Context(), "[WeChatKF] Failed to decrypt echostr: %v", err)
		c.String(http.StatusBadRequest, "decrypt failed")
		return true
	}
	c.String(http.StatusOK, string(decrypted))
	return true
}

// ParseCallback parses a WeChat KF callback into a unified IncomingMessage.
func (a *Adapter) ParseCallback(c *gin.Context) (*im.IncomingMessage, error) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var body callbackRequestBody
	if err := xml.Unmarshal(bodyBytes, &body); err != nil {
		return nil, fmt.Errorf("unmarshal xml: %w", err)
	}

	decrypted, err := a.decrypt(body.Encrypt)
	if err != nil {
		return nil, fmt.Errorf("decrypt message: %w", err)
	}

	logger.Debugf(c.Request.Context(), "[WeChatKF] Raw decrypted callback: %s", string(decrypted))

	var msg wechatKFMessage
	if err := xml.Unmarshal(decrypted, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted message: %w", err)
	}

	logger.Debugf(c.Request.Context(), "[WeChatKF] Parsed message: msgid=%s msgtype=%s from=%s content=%q",
		msg.MsgID, msg.MsgType, msg.FromUserName, msg.Content)

	switch msg.MsgType {
	case "text":
		return &im.IncomingMessage{
			Platform:    im.PlatformWechatKF,
			MessageType: im.MessageTypeText,
			UserID:      msg.FromUserName,
			Content:     strings.TrimSpace(msg.Content),
			MessageID:   msg.MsgID,
		}, nil

	case "image":
		if msg.PicUrl == "" && msg.MediaId == "" {
			return nil, nil
		}
		fileKey := msg.PicUrl
		if fileKey == "" {
			fileKey = msg.MediaId
		}
		return &im.IncomingMessage{
			Platform:    im.PlatformWechatKF,
			MessageType: im.MessageTypeImage,
			UserID:      msg.FromUserName,
			MessageID:   msg.MsgID,
			FileKey:     fileKey,
			FileName:    msg.MsgID + ".png",
		}, nil

	case "file":
		if msg.MediaId == "" {
			return nil, nil
		}
		return &im.IncomingMessage{
			Platform:    im.PlatformWechatKF,
			MessageType: im.MessageTypeFile,
			UserID:      msg.FromUserName,
			MessageID:   msg.MsgID,
			FileKey:     msg.MediaId,
		}, nil

	default:
		logger.Infof(c.Request.Context(), "[WeChatKF] Ignoring unsupported message type: %s", msg.MsgType)
		return nil, nil
	}
}

// SendReply sends a reply via the WeChat KF send_msg API.
func (a *Adapter) SendReply(ctx context.Context, incoming *im.IncomingMessage, reply *im.ReplyMessage) error {
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	payload := map[string]interface{}{
		"touser":    incoming.UserID,
		"open_kfid": a.openKFID,
		"msgtype":   "text",
		"text": map[string]string{
			"content": reply.Content,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	sendURL := fmt.Sprintf("%s/cgi-bin/kf/send_msg?access_token=%s", a.apiBaseURL, accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("wechatkf api error: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}
	return nil
}

// DownloadFile downloads a file/image from WeChat KF.
func (a *Adapter) DownloadFile(ctx context.Context, msg *im.IncomingMessage) (io.ReadCloser, string, error) {
	if msg.FileKey == "" {
		return nil, "", fmt.Errorf("no file key in message")
	}

	fileName := msg.FileName
	if fileName == "" {
		fileName = msg.FileKey
	}

	if strings.HasPrefix(msg.FileKey, "http://") || strings.HasPrefix(msg.FileKey, "https://") {
		return downloadFromURL(ctx, msg.FileKey, fileName, a.extraAllowedHost)
	}

	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("get access token: %w", err)
	}

	apiURL := fmt.Sprintf("%s/cgi-bin/media/get?access_token=%s&media_id=%s",
		a.apiBaseURL, accessToken, msg.FileKey)
	return downloadFromURL(ctx, apiURL, fileName, a.extraAllowedHost)
}

// getAccessToken retrieves the WeChat KF access token with caching.
func (a *Adapter) getAccessToken(ctx context.Context) (string, error) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	if a.tokenCache != "" && time.Now().Before(a.tokenExpAt) {
		return a.tokenCache, nil
	}

	payload := map[string]string{
		"corpid": a.corpID,
		"secret": a.kfSecret,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal token request: %w", err)
	}

	tokenURL := fmt.Sprintf("%s/cgi-bin/kf/token", a.apiBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request access token: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if result.ErrCode != 0 {
		return "", fmt.Errorf("get token error: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}

	a.tokenCache = result.AccessToken
	ttl := time.Duration(result.ExpiresIn) * time.Second
	if ttl > 5*time.Minute {
		ttl -= 5 * time.Minute
	}
	a.tokenExpAt = time.Now().Add(ttl)

	return a.tokenCache, nil
}

// verifySignature verifies the callback signature using constant-time comparison.
func (a *Adapter) verifySignature(signature, timestamp, nonce, encrypt string) bool {
	parts := []string{a.token, timestamp, nonce, encrypt}
	sort.Strings(parts)
	combined := strings.Join(parts, "")

	hash := sha1.New()
	hash.Write([]byte(combined))
	computed := fmt.Sprintf("%x", hash.Sum(nil))

	return hmac.Equal([]byte(computed), []byte(signature))
}

// decrypt decrypts an AES-encrypted message (same algorithm as WeCom).
func (a *Adapter) decrypt(encrypted string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(a.aesKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := a.aesKey[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	padLen := int(ciphertext[len(ciphertext)-1])
	if padLen > aes.BlockSize || padLen == 0 || padLen > len(ciphertext) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := 0; i < padLen; i++ {
		if ciphertext[len(ciphertext)-1-i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	plaintext := ciphertext[:len(ciphertext)-padLen]

	if len(plaintext) < 20 {
		return nil, fmt.Errorf("plaintext too short")
	}

	msgLen := binary.BigEndian.Uint32(plaintext[16:20])
	if uint32(len(plaintext)) < 20+msgLen {
		return nil, fmt.Errorf("message length mismatch")
	}

	msgBytes := plaintext[20 : 20+msgLen]

	corpIDBytes := plaintext[20+msgLen:]
	if string(corpIDBytes) != a.corpID {
		return nil, fmt.Errorf("corp_id mismatch: expected %s, got %s", a.corpID, string(corpIDBytes))
	}

	return msgBytes, nil
}

// callbackRequestBody is the XML structure of a callback request body.
type callbackRequestBody struct {
	XMLName xml.Name `xml:"xml"`
	Encrypt string   `xml:"Encrypt"`
}

// wechatKFMessage is the decrypted WeChat KF message structure.
type wechatKFMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`   // open_kfid
	FromUserName string   `xml:"FromUserName"` // external_userid
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
	Content      string   `xml:"Content"`
	PicUrl       string   `xml:"PicUrl"`
	MediaId      string   `xml:"MediaId"`
	MsgID        string   `xml:"MsgId"`
}

// ──────────────────────────────────────────────────────────────────────
// SSRF protection and download helpers
// ──────────────────────────────────────────────────────────────────────

func extraHostFromEndpoint(endpoint, defaultEndpoint string) string {
	if endpoint == "" || endpoint == defaultEndpoint {
		return ""
	}
	if u, err := url.Parse(endpoint); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

func validateEndpointURL(endpoint, defaultEndpoint, requiredScheme string) error {
	if endpoint == "" || endpoint == defaultEndpoint {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if u.Scheme != requiredScheme {
		return fmt.Errorf("endpoint must use %s:// scheme, got %s://", requiredScheme, u.Scheme)
	}
	if err := secutils.ValidateURLForSSRF(endpoint); err != nil {
		return fmt.Errorf("%w (for private deployments on internal networks, add the hostname to SSRF_WHITELIST)", err)
	}
	return nil
}

var allowedIMAPIHosts = []string{
	"qyapi.weixin.qq.com",
	"api.weixin.qq.com",
	"open.work.weixin.qq.com",
	"novac2c.cdn.weixin.qq.com",
	"ilinkai.weixin.qq.com",
}

func isAllowedIMAPIHost(rawURL string, extraHost string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(u.Hostname())
	if extraHost != "" && hostname == extraHost {
		return true
	}
	for _, allowed := range allowedIMAPIHosts {
		if hostname == allowed {
			return true
		}
	}
	return false
}

func downloadFromURL(ctx context.Context, rawURL, fileName string, extraAllowedHost string) (io.ReadCloser, string, error) {
	if !isAllowedIMAPIHost(rawURL, extraAllowedHost) {
		if err := secutils.ValidateURLForSSRF(rawURL); err != nil {
			return nil, "", fmt.Errorf("URL rejected for security reasons: %v", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("download: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, "", fmt.Errorf("download failed: status=%d", resp.StatusCode)
	}

	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn := params["filename"]; fn != "" {
				fileName = fn
			}
		} else {
			if idx := strings.Index(cd, "filename="); idx >= 0 {
				extracted := strings.Trim(cd[idx+len("filename="):], "\" ")
				if extracted != "" {
					fileName = extracted
				}
			}
		}
	}

	if strings.Contains(fileName, "%") {
		if decoded, err := url.QueryUnescape(fileName); err == nil && decoded != "" {
			fileName = decoded
		}
	}

	if !strings.Contains(fileName, ".") {
		if u, err := url.Parse(rawURL); err == nil {
			base := path.Base(u.Path)
			if base != "" && base != "." && base != "/" && strings.Contains(base, ".") {
				if decoded, err := url.QueryUnescape(base); err == nil {
					fileName = decoded
				} else {
					fileName = base
				}
			}
		}
	}

	if !strings.Contains(fileName, ".") {
		if ext := contentTypeToExt(resp.Header.Get("Content-Type")); ext != "" {
			fileName = fileName + "." + ext
		}
	}

	return resp.Body, fileName, nil
}

func contentTypeToExt(ct string) string {
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	ct = strings.ToLower(ct)

	mapping := map[string]string{
		"application/pdf":    "pdf",
		"application/msword": "doc",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
		"application/vnd.ms-excel": "xls",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         "xlsx",
		"application/vnd.ms-powerpoint":                                             "ppt",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
		"text/plain":    "txt",
		"text/markdown": "md",
		"text/csv":      "csv",
		"image/png":     "png",
		"image/jpeg":    "jpg",
		"image/gif":     "gif",
		"image/webp":    "webp",
	}

	return mapping[ct]
}
