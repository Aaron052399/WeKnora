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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	agenttools "github.com/Tencent/WeKnora/internal/agent/tools"
	"github.com/Tencent/WeKnora/internal/im"
	"github.com/Tencent/WeKnora/internal/logger"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/gin-gonic/gin"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

const defaultAPIBaseURL = "https://qyapi.weixin.qq.com"

// ──────────────────────────────────────────────────────────────────────
// 转人工意图识别
// ──────────────────────────────────────────────────────────────────────

// transferKeywords 转人工关键词列表
var transferKeywords = []string{
	"转人工", "人工客服", "转接人工", "人工服务",
	"找人工", "真人客服", "真人", "要人工",
	"不要机器人", "不想跟机器人", "换人工", "接人工",
}

// isTransferIntent 检查消息是否包含转人工意图
func isTransferIntent(content string) bool {
	for _, keyword := range transferKeywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

// ──────────────────────────────────────────────────────────────────────
// 转人工状态管理
// ──────────────────────────────────────────────────────────────────────

const menuExpire = 5 * time.Minute // 菜单有效期

type transferState struct {
	status string    // menu_sent, transferring
	sentAt time.Time // 菜单发送时间
}

var transferStates = sync.Map{} // key: "open_kfid:external_userid" -> *transferState

func getTransferState(cacheKey string) *transferState {
	val, ok := transferStates.Load(cacheKey)
	if !ok {
		return nil
	}
	state := val.(*transferState)
	// 检查是否超时
	if time.Since(state.sentAt) > menuExpire {
		transferStates.Delete(cacheKey)
		return nil
	}
	return state
}

func setTransferState(cacheKey, status string) {
	transferStates.Store(cacheKey, &transferState{
		status: status,
		sentAt: time.Now(),
	})
}

func clearTransferState(cacheKey string) {
	transferStates.Delete(cacheKey)
}

// Adapter implements im.Adapter for WeChat Customer Service in webhook mode.
type Adapter struct {
	corpID           string
	appSecret        string // 自建应用的 secret，用于获取 access_token
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
func NewAdapter(corpID, appSecret, token, encodingAESKey, apiBaseURL string) (*Adapter, error) {
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
		appSecret:        appSecret,
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

	logger.Infof(c.Request.Context(), "[WeChatKF] Parsed callback: msgid=%s msgtype=%s event=%s from=%s open_kfid=%s content=%q",
		msg.MsgID, msg.MsgType, msg.Event, msg.FromUserName, msg.OpenKfId, msg.Content)

	// open_kfid 从回调事件或 ToUserName 中获取，用于发送回复
	openKfId := msg.OpenKfId
	if openKfId == "" {
		// 非 event 类型的回调中，ToUserName 就是 open_kfid
		openKfId = msg.ToUserName
	}

	switch msg.MsgType {
	case "text":
		return &im.IncomingMessage{
			Platform:    im.PlatformWechatKF,
			MessageType: im.MessageTypeText,
			UserID:      msg.FromUserName,
			Content:     strings.TrimSpace(msg.Content),
			MessageID:   msg.MsgID,
			Extra:       map[string]string{"open_kfid": openKfId},
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
			Extra:       map[string]string{"open_kfid": openKfId},
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
			Extra:       map[string]string{"open_kfid": openKfId},
		}, nil

	case "event":
		if msg.Event == "kf_msg_or_event" {
			return a.handleKfMsgOrEvent(c.Request.Context(), msg)
		}
		logger.Infof(c.Request.Context(), "[WeChatKF] Ignoring unsupported event: %s", msg.Event)
		return nil, nil

	default:
		logger.Infof(c.Request.Context(), "[WeChatKF] Ignoring unsupported message type: %s", msg.MsgType)
		return nil, nil
	}
}

// handleKfMsgOrEvent 处理 kf_msg_or_event 事件，调用 sync_msg API 获取消息内容
func (a *Adapter) handleKfMsgOrEvent(ctx context.Context, event wechatKFMessage) (*im.IncomingMessage, error) {
	if event.Token == "" {
		return nil, fmt.Errorf("callback event missing Token field")
	}

	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get access token: %w", err)
	}

	// 构造 sync_msg 请求
	payload := map[string]interface{}{
		"token":     event.Token,
		"open_kfid": event.OpenKfId,
		"limit":     1000,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal sync_msg payload: %w", err)
	}

	syncURL := fmt.Sprintf("%s/cgi-bin/kf/sync_msg?access_token=%s", a.apiBaseURL, accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, syncURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("create sync_msg request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call sync_msg: %w", err)
	}
	defer resp.Body.Close()

	var result syncMsgResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode sync_msg response: %w", err)
	}
	if result.ErrCode != 0 {
		return nil, fmt.Errorf("sync_msg error: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}

	logger.Infof(ctx, "[WeChatKF] sync_msg returned %d messages, has_more=%d, open_kfid=%s",
		len(result.MsgList), result.HasMore, event.OpenKfId)

	// openKfId 从回调事件中获取，用于发送回复
	openKfId := event.OpenKfId

	// 遍历消息列表，找到最新的客户文本消息
	for i := len(result.MsgList) - 1; i >= 0; i-- {
		msg := result.MsgList[i]

		// 处理菜单事件 (origin=4, msgtype=menu_event)
		if msg.Origin == 4 && msg.MsgType == "menu_event" && msg.MenuEvent != nil {
			logger.Infof(ctx, "[WeChatKF] Menu event received: menu_key=%s menu_id=%s userid=%s",
				msg.MenuEvent.MenuKey, msg.MenuEvent.MenuID, msg.ExternalUserid)
			// 菜单事件不进入 AI 处理流程
			return nil, nil
		}

		// origin=3 表示客户发送的消息
		if msg.Origin != 3 {
			continue
		}

		logger.Infof(ctx, "[WeChatKF] Found customer message: msgid=%s msgtype=%s userid=%s content_len=%d",
			msg.MsgID, msg.MsgType, msg.ExternalUserid, len(msg.Content.Content))

		if msg.ExternalUserid == "" {
			logger.Warnf(ctx, "[WeChatKF] Customer message has empty external_userid, skipping: msgid=%s", msg.MsgID)
			continue
		}

		switch msg.MsgType {
		case "text":
			content := strings.TrimSpace(msg.Content.Content)
			if content == "" {
				continue
			}

			cacheKey := fmt.Sprintf("%s:%s", openKfId, msg.ExternalUserid)

			// 检查是否为 click 响应（用户点击菜单按钮）
			if content == "transfer_confirm" {
				state := getTransferState(cacheKey)
				if state != nil && state.status == "menu_sent" {
					// 执行转接
					setTransferState(cacheKey, "transferring")
					target, err := a.SelectTransferTarget(ctx, openKfId)
					if err != nil {
						logger.Errorf(ctx, "[WeChatKF] No available agent: %v", err)
						clearTransferState(cacheKey)
						_ = a.SendTextReply(ctx, openKfId, msg.ExternalUserid, "抱歉，当前没有可用的人工客服，请稍后重试。")
						return nil, nil
					}
					if err := a.TransferToAgent(ctx, openKfId, msg.ExternalUserid, target, "用户请求转人工"); err != nil {
						logger.Errorf(ctx, "[WeChatKF] Transfer failed: %v", err)
						clearTransferState(cacheKey)
						_ = a.SendTextReply(ctx, openKfId, msg.ExternalUserid, "转接人工客服失败，请稍后重试。")
						return nil, nil
					}
					clearTransferState(cacheKey)
					_ = a.SendTextReply(ctx, openKfId, msg.ExternalUserid, "正在为您转接人工客服，请稍候...")
					return nil, nil
				}
				// 状态不对，忽略
				return nil, nil
			}

			if content == "transfer_cancel" {
				clearTransferState(cacheKey)
				// 继续正常 AI 对话，不返回 nil
			}

			// 检查转人工意图
			if isTransferIntent(content) {
				state := getTransferState(cacheKey)
				if state == nil {
					// 首次触发，发送菜单消息
					if err := a.SendMenuMessage(ctx, openKfId, msg.ExternalUserid, "您好，请问需要转接人工客服吗？"); err != nil {
						logger.Errorf(ctx, "[WeChatKF] Send menu failed: %v", err)
						// 发送菜单失败，继续正常 AI 流程
					} else {
						setTransferState(cacheKey, "menu_sent")
						return nil, nil // 菜单已发送，不进入 AI
					}
				} else if state.status == "menu_sent" {
					// 已发送菜单，提示用户点击
					_ = a.SendTextReply(ctx, openKfId, msg.ExternalUserid, "请点击上方菜单按钮确认转人工。")
					return nil, nil
				} else if state.status == "transferring" {
					// 正在转接中
					_ = a.SendTextReply(ctx, openKfId, msg.ExternalUserid, "正在转接中，请稍候...")
					return nil, nil
				}
			}

			return &im.IncomingMessage{
				Platform:    im.PlatformWechatKF,
				MessageType: im.MessageTypeText,
				UserID:      msg.ExternalUserid,
				Content:     content,
				MessageID:   msg.MsgID,
				Extra:       map[string]string{"open_kfid": openKfId},
			}, nil

		case "image":
			if msg.Image.MediaID == "" {
				continue
			}
			return &im.IncomingMessage{
				Platform:    im.PlatformWechatKF,
				MessageType: im.MessageTypeImage,
				UserID:      msg.ExternalUserid,
				MessageID:   msg.MsgID,
				FileKey:     msg.Image.MediaID,
				FileName:    msg.MsgID + ".png",
				Extra:       map[string]string{"open_kfid": openKfId},
			}, nil

		case "file":
			if msg.File.MediaID == "" {
				continue
			}
			return &im.IncomingMessage{
				Platform:    im.PlatformWechatKF,
				MessageType: im.MessageTypeFile,
				UserID:      msg.ExternalUserid,
				MessageID:   msg.MsgID,
				FileKey:     msg.File.MediaID,
				Extra:       map[string]string{"open_kfid": openKfId},
			}, nil
		}
	}

	logger.Infof(ctx, "[WeChatKF] No new customer messages found in sync_msg response")
	return nil, nil
}

// stripMarkdown 将 Markdown 格式文本转换为纯文本（微信客服不支持 Markdown）
func stripMarkdown(text string) string {
	if text == "" {
		return text
	}
	// 移除代码块 ```code```
	text = regexp.MustCompile("(?s)```.*?```").ReplaceAllString(text, "$1")
	// 移除标题标记 ### ##
	text = regexp.MustCompile(`#{1,6}\s+`).ReplaceAllString(text, "")
	// 移除加粗 **text** 或 __text__
	text = regexp.MustCompile(`\*\*(.+?)\*\*`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`__(.+?)__`).ReplaceAllString(text, "$1")
	// 移除斜体 *text* 或 _text_
	text = regexp.MustCompile(`\*(.+?)\*`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`_(.+?)_`).ReplaceAllString(text, "$1")
	// 移除删除线 ~~text~~
	text = regexp.MustCompile(`~~(.+?)~~`).ReplaceAllString(text, "$1")
	// 移除行内代码 `code`
	text = regexp.MustCompile("`(.+?)`").ReplaceAllString(text, "$1")
	// 移除链接 [text](url) → text
	text = regexp.MustCompile(`\[(.+?)\]\(.+?\)`).ReplaceAllString(text, "$1")
	// 移除图片 ![alt](url)
	text = regexp.MustCompile(`!\[.*?\]\(.+?\)`).ReplaceAllString(text, "")
	// 移除引用 >
	text = regexp.MustCompile(`(?m)^>\s+`).ReplaceAllString(text, "")
	// 移除分割线 --- 或 ***
	text = regexp.MustCompile(`(?m)^[-*_]{3,}$`).ReplaceAllString(text, "")
	// 无序列表 - 或 * 开头 → • 开头（微信客服能正常显示）
	text = regexp.MustCompile(`(?m)^[\s]*[-*]\s+`).ReplaceAllString(text, "• ")
	// 嵌套有序列表（有缩进）→ 1) 格式，保留层级感
	text = regexp.MustCompile(`(?m)^\s+(\d+)\.\s+`).ReplaceAllString(text, "$1) ")
	// 顶层有序列表（无缩进）→ 保留 1. 格式不动
	return strings.TrimSpace(text)
}

// SendReply sends a reply via the WeChat KF send_msg API.
func (a *Adapter) SendReply(ctx context.Context, incoming *im.IncomingMessage, reply *im.ReplyMessage) error {
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	// 从回调事件中获取 open_kfid，而不是使用配置中的值
	openKfId := ""
	if incoming.Extra != nil {
		openKfId = incoming.Extra["open_kfid"]
	}
	if openKfId == "" {
		return fmt.Errorf("open_kfid not found in message Extra, cannot send reply (userid=%s)", incoming.UserID)
	}
	if incoming.UserID == "" {
		return fmt.Errorf("touser (external_userid) is empty, cannot send reply (open_kfid=%s)", openKfId)
	}

	reply.Content = agenttools.StripThinkBlocks(reply.Content)
	// 微信客服不支持 Markdown 格式，转换为纯文本
	reply.Content = stripMarkdown(reply.Content)

	logger.Infof(ctx, "[WeChatKF] Sending reply: touser=%s open_kfid=%s content_len=%d",
		incoming.UserID, openKfId, len(reply.Content))

	payload := map[string]interface{}{
		"touser":    incoming.UserID,
		"open_kfid": openKfId,
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
		logger.Errorf(ctx, "[WeChatKF] send_msg failed: errcode=%d errmsg=%s touser=%s open_kfid=%s",
			result.ErrCode, result.ErrMsg, incoming.UserID, openKfId)
		return fmt.Errorf("wechatkf api error: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}

	logger.Infof(ctx, "[WeChatKF] Reply sent successfully: touser=%s open_kfid=%s", incoming.UserID, openKfId)
	return nil
}

// SendMenuMessage sends a menu message (msgmenu) to the user.
func (a *Adapter) SendMenuMessage(ctx context.Context, openKfID, externalUserid, headContent string) error {
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	payload := map[string]interface{}{
		"touser":    externalUserid,
		"open_kfid": openKfID,
		"msgid":     fmt.Sprintf("menu_%d", time.Now().UnixMilli()),
		"msgtype":   "msgmenu",
		"msgmenu": map[string]interface{}{
			"head_content": headContent,
			"list": []map[string]interface{}{
				{
					"type": "click",
					"click": map[string]interface{}{
						"id":      "transfer_confirm",
						"content": "确认转人工",
					},
				},
				{
					"type": "click",
					"click": map[string]interface{}{
						"id":      "transfer_cancel",
						"content": "继续咨询",
					},
				},
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal menu payload: %w", err)
	}

	sendURL := fmt.Sprintf("%s/cgi-bin/kf/send_msg?access_token=%s", a.apiBaseURL, accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("create menu request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send menu message: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode menu response: %w", err)
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("send menu failed: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}

	return nil
}

// SendTextReply sends a simple text message to a user.
func (a *Adapter) SendTextReply(ctx context.Context, openKfID, externalUserid, content string) error {
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	payload := map[string]interface{}{
		"touser":    externalUserid,
		"open_kfid": openKfID,
		"msgtype":   "text",
		"text": map[string]string{
			"content": content,
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
		return fmt.Errorf("send text reply failed: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}

	return nil
}

// GetAgentList retrieves the list of agents for a KF account.
func (a *Adapter) GetAgentList(ctx context.Context, openKfID string) ([]AgentInfo, error) {
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get access token: %w", err)
	}

	payload := map[string]interface{}{
		"open_kfid": openKfID,
		"offset":    0,
		"limit":     100,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/cgi-bin/kf/user/list?access_token=%s", a.apiBaseURL, accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call API: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode  int         `json:"errcode"`
		ErrMsg   string      `json:"errmsg"`
		UserList []AgentInfo `json:"user_list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if result.ErrCode != 0 {
		return nil, fmt.Errorf("API error: code=%d msg=%s", result.ErrCode, result.ErrMsg)
	}

	return result.UserList, nil
}

// AgentInfo holds agent information from the KF user list API.
type AgentInfo struct {
	UserID             string `json:"userid"`
	Name               string `json:"name"`
	Status             int    `json:"status"` // 1=online, 2=busy, 3=away
	ObotTransferReject bool   `json:"obot_transfer_reject"`
}

// SelectTransferTarget selects an available agent for transfer.
func (a *Adapter) SelectTransferTarget(ctx context.Context, openKfID string) (string, error) {
	agents, err := a.GetAgentList(ctx, openKfID)
	if err != nil {
		return "", fmt.Errorf("get agent list: %w", err)
	}

	// 优先选择在线且不拒绝机器人转接的客服
	for _, agent := range agents {
		if agent.Status == 1 && !agent.ObotTransferReject {
			return agent.UserID, nil
		}
	}

	// 没有在线的，选择不拒绝机器人转接的客服（忙碌或离开）
	for _, agent := range agents {
		if !agent.ObotTransferReject {
			return agent.UserID, nil
		}
	}

	return "", fmt.Errorf("no available agent found")
}

// TransferToAgent transfers the current conversation to a human agent.
func (a *Adapter) TransferToAgent(ctx context.Context, openKfID, externalUserid, userid, remark string) error {
	accessToken, err := a.getAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get access token: %w", err)
	}

	payload := map[string]interface{}{
		"open_kfid":       openKfID,
		"external_userid": externalUserid,
		"userid":          userid,
		"need_record":     1,
		"remark":          remark,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal transfer payload: %w", err)
	}

	transferURL := fmt.Sprintf("%s/cgi-bin/kf/user/transfer?access_token=%s", a.apiBaseURL, accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, transferURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("create transfer request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("call transfer API: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode transfer response: %w", err)
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("transfer error: code=%d msg=%s", result.ErrCode, result.ErrMsg)
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

// getAccessToken retrieves the WeChat access token with caching.
func (a *Adapter) getAccessToken(ctx context.Context) (string, error) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	if a.tokenCache != "" && time.Now().Before(a.tokenExpAt) {
		return a.tokenCache, nil
	}

	tokenURL := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", a.apiBaseURL, a.corpID, a.appSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

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
// WeCom uses AES-256-CBC with PKCS#7 padding (block size 32).
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

	// WeCom uses PKCS#7 padding with block size 32 (not standard AES block size 16)
	const wecomPKCS7BlockSize = 32
	padLen := int(ciphertext[len(ciphertext)-1])
	if padLen > wecomPKCS7BlockSize || padLen == 0 || padLen > len(ciphertext) {
		return nil, fmt.Errorf("invalid padding: padLen=%d", padLen)
	}
	for i := 0; i < padLen; i++ {
		if ciphertext[len(ciphertext)-1-i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding byte at position %d", len(ciphertext)-1-i)
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
	Event        string   `xml:"Event"`       // 事件类型，如 kf_msg_or_event
	Token        string   `xml:"Token"`       // 回调事件中的 token，用于 sync_msg
	OpenKfId     string   `xml:"OpenKfId"`    // 客服账号 ID
}

// syncMsgResponse 是 sync_msg API 的响应结构
type syncMsgResponse struct {
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
	NextCursor string `json:"next_cursor"`
	HasMore    int    `json:"has_more"`
	MsgList    []struct {
		MsgID          string `json:"msgid"`
		OpenKfID       string `json:"open_kfid"`
		ExternalUserid string `json:"external_userid"`
		SendTime       int64  `json:"send_time"`
		Origin         int    `json:"origin"` // 3=客户，4=系统事件，5=接待人员
		MsgType        string `json:"msgtype"`
		Content        struct {
			Content string `json:"content"`
		} `json:"text,omitempty"`
		Image struct {
			MediaID string `json:"media_id"`
		} `json:"image,omitempty"`
		File struct {
			MediaID string `json:"media_id"`
		} `json:"file,omitempty"`
		MenuEvent *struct {
			EventType int    `json:"event_type"`
			MenuID    string `json:"menu_id"`
			MenuKey   string `json:"menu_key"`
		} `json:"menu_event,omitempty"`
	} `json:"msg_list"`
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
