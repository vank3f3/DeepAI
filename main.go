package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
)

// ============ 配置结构与辅助函数 ============

// Config 根配置
type Config struct {
	ThinkingServices []ThinkingService  `mapstructure:"thinking_services"`
	Channels         map[string]Channel `mapstructure:"channels"`
	Global           GlobalConfig       `mapstructure:"global"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Default       string `mapstructure:"default"`
	AllowInsecure bool   `mapstructure:"allow_insecure"`
}

// ThinkingService 思考服务配置
type ThinkingService struct {
	ID      int    `mapstructure:"id"`
	Name    string `mapstructure:"name"`
	Model   string `mapstructure:"model"`
	BaseURL string `mapstructure:"base_url"`
	APIPath string `mapstructure:"api_path"`
	APIKey  string `mapstructure:"api_key"`
	Timeout int    `mapstructure:"timeout"`
	Retry   int    `mapstructure:"retry"`
	Weight  int    `mapstructure:"weight"`
	Proxy   string `mapstructure:"proxy"`

	// 该字段表示思考服务的模式。
	// 示例值： "auto", "standard", "nonstandard", "guided", "non-thinking"
	// 如果设置为 non-thinking，则系统内部会自动当作 nonstandard 处理，但日志中会标识出来
	Mode string `mapstructure:"mode"`
}

// GetFullURL 获取思考服务的完整调用路径
func (s *ThinkingService) GetFullURL() string {
	return s.BaseURL + s.APIPath
}

// Channel 后端 LLM 通道配置
type Channel struct {
	Name    string `mapstructure:"name"`
	BaseURL string `mapstructure:"base_url"`
	APIPath string `mapstructure:"api_path"`
	Timeout int    `mapstructure:"timeout"`
	Proxy   string `mapstructure:"proxy"`

	// 通道模式: "compatible"（旧版兼容） 或 "enhanced"（新版增强）
	Mode string `mapstructure:"mode"`

	// 针对通道内特定模型的配置（可选），例如指定某些正则匹配的模型使用不同模式
	ModelConfig []ModelConfig `mapstructure:"model_config"`
}

// ModelConfig 针对通道内特定模型的配置
type ModelConfig struct {
	ModelPattern string `mapstructure:"model_pattern"`
	Mode         string `mapstructure:"mode"`
}

// GetFullURL 通道完整调用路径
func (c *Channel) GetFullURL() string {
	return c.BaseURL + c.APIPath
}

// GlobalConfig 全局配置
type GlobalConfig struct {
	MaxRetries     int            `mapstructure:"max_retries"`
	DefaultTimeout int            `mapstructure:"default_timeout"`
	ErrorCodes     struct {
		RetryOn []int `mapstructure:"retry_on"`
	} `mapstructure:"error_codes"`

	Log      LogConfig      `mapstructure:"log"`
	Server   ServerConfig   `mapstructure:"server"`
	Proxy    ProxyConfig    `mapstructure:"proxy"`
	Thinking ThinkingConfig `mapstructure:"thinking"`
	Channel  ChannelConfig  `mapstructure:"channel"`
}

// ChannelConfig 通道全局配置
type ChannelConfig struct {
	DefaultMode string `mapstructure:"default_mode"` // 如果 Channel 未指定 mode，则使用该默认值（例如 "compatible"）
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port         int    `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	IdleTimeout  int    `mapstructure:"idle_timeout"`
}

// ThinkingConfig 思考链相关配置
type ThinkingConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	AddToAllRequests bool   `mapstructure:"add_to_all_requests"`
	Timeout          int    `mapstructure:"timeout"`
	ChainPreProcess  bool   `mapstructure:"chain_preprocess"` // 是否对思考链做预处理
	DefaultMode      string `mapstructure:"default_mode"`      // 全局默认思考模式，例如 "nonstandard"
}

// LogConfig 日志配置
type LogConfig struct {
	Level    string      `mapstructure:"level"`
	Format   string      `mapstructure:"format"`
	Output   string      `mapstructure:"output"`
	FilePath string      `mapstructure:"file_path"`
	Debug    DebugConfig `mapstructure:"debug"`
}

// DebugConfig 调试日志配置
type DebugConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	PrintRequest     bool `mapstructure:"print_request"`
	PrintResponse    bool `mapstructure:"print_response"`
	MaxContentLength int  `mapstructure:"max_content_length"`
}

// ============ OpenAI兼容API相关结构 ============

// ChatCompletionRequest /v1/chat/completions 请求体
type ChatCompletionRequest struct {
	Model       string                  `json:"model"`
	Messages    []ChatCompletionMessage `json:"messages"`
	Temperature float64                 `json:"temperature,omitempty"`
	MaxTokens   int                     `json:"max_tokens,omitempty"`
	Stream      bool                    `json:"stream,omitempty"`

	// 内部使用，不序列化
	APIKey string `json:"-"`
}

// ChatCompletionMessage 聊天消息
type ChatCompletionMessage struct {
	Role             string      `json:"role"`
	Content          string      `json:"content"`
	ReasoningContent interface{} `json:"reasoning_content,omitempty"`
}

// ChatCompletionResponse /v1/chat/completions 响应体
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Choice 单条生成
type Choice struct {
	Index        int                   `json:"index"`
	Message      ChatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
}

// Usage token统计
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ============ 请求日志辅助 ============

type RequestLogger struct {
	RequestID string
	StartTime time.Time
	logs      []string
	config    *Config
}

func NewRequestLogger(config *Config) *RequestLogger {
	return &RequestLogger{
		RequestID: uuid.New().String(),
		StartTime: time.Now(),
		logs:      make([]string, 0),
		config:    config,
	}
}

func (l *RequestLogger) Log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.logs = append(l.logs, fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), msg))
	log.Printf("[RequestID: %s] %s", l.RequestID, msg)
}

func (l *RequestLogger) LogContent(tag string, content interface{}, maxLen int) {
	if l.config == nil || !l.config.Global.Log.Debug.Enabled {
		return
	}
	b, _ := json.Marshal(content)
	s := string(b)
	if len(s) > maxLen {
		s = s[:maxLen] + "...(truncated)"
	}
	// 屏蔽 API Key
	re := regexp.MustCompile(`"api_key":\s*"[^"]+"`)
	s = re.ReplaceAllString(s, `"api_key":"****"`)
	l.Log("%s:\n%s", tag, s)
}

// ============ 思考链处理结构 ============

// ThinkingResponse 用于保存“思考服务”的输出（思考链 + 最终回答）
type ThinkingResponse struct {
	Content                string // 思考服务的最终回答文本
	ReasoningContent       string // 原始 reasoning_content（若为标准思考模型）或空
	ActualReasoningContent string // 最终给后端模型使用的思考链
	IsStandardMode         bool   // 是否属于标准思考模型（有 reasoning_content 字段）
}

// 预处理思考链，可根据需求过滤无用内容
func preprocessReasoningChain(chain string) string {
	lines := strings.Split(chain, "\n")
	var processed []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		// 可在此添加更多过滤逻辑
		if strings.HasPrefix(ln, "Note:") {
			continue
		}
		processed = append(processed, ln)
	}
	return strings.Join(processed, "\n")
}

// ============ 模式/逻辑判断函数 ============

// determineThinkingMode 确定思考服务的模式
func determineThinkingMode(svc ThinkingService, globalDefault string) string {
	mode := svc.Mode
	// 如果未指定或设为 "auto"，则使用全局默认
	if mode == "" || mode == "auto" {
		mode = globalDefault
	}
	// 如果模式为 "non-thinking"，目前自动识别2和3比较困难，
	// 所以这里统一按 nonstandard 处理，但在日志中标识出原始值
	if mode == "non-thinking" {
		log.Printf("Thinking service '%s' is set to non-thinking mode; treating as nonstandard.", svc.Name)
		mode = "nonstandard"
	}
	return mode
}

// determineChannelMode 确定通道模式：首先检查模型配置，其次检查通道自身，再使用全局默认
func determineChannelMode(ch Channel, model string, globalDefault string) string {
	// (1) 检查是否有针对特定模型的配置
	for _, mc := range ch.ModelConfig {
		if matched, _ := regexp.MatchString(mc.ModelPattern, model); matched {
			return mc.Mode
		}
	}
	// (2) 如果通道本身有 mode，直接使用
	if ch.Mode != "" {
		return ch.Mode
	}
	// (3) 否则使用全局默认
	if globalDefault == "" {
		return "compatible" // 默认回退
	}
	return globalDefault
}

// ============ 服务器主体结构 ============

type Server struct {
	config *Config
	srv    *http.Server
}

// 全局随机数生成器与互斥锁（用于加权随机选服务）
var (
	randMu  sync.Mutex
	randGen = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func NewServer(cfg *Config) *Server {
	return &Server{
		config: cfg,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/chat/completions", s.handleOpenAIRequests)
	mux.HandleFunc("/v1/models", s.handleOpenAIRequests)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	s.srv = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Global.Server.Host, s.config.Global.Server.Port),
		Handler:      mux,
		ReadTimeout:  time.Duration(s.config.Global.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Global.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.Global.Server.IdleTimeout) * time.Second,
	}

	log.Printf("Server starting on %s", s.srv.Addr)
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// handleOpenAIRequests 核心处理入口
func (s *Server) handleOpenAIRequests(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/chat/completions" && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/v1/models" && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := NewRequestLogger(s.config)

	// 1. 从 Authorization 头中获取 channelID 和真实 API Key
	fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	realKey := extractRealAPIKey(fullAPIKey)
	channelID := extractChannelID(fullAPIKey)
	logger.Log("Incoming request: %s (APIKey=%s) channelID=%s",
		r.URL.Path, logSafeKey(fullAPIKey), channelID)

	// 2. 寻找目标 Channel
	ch, ok := s.config.Channels[channelID]
	if !ok {
		http.Error(w, "Invalid channel", http.StatusBadRequest)
		return
	}

	// 3. 如果是 /v1/models 请求，直接转发
	if r.URL.Path == "/v1/models" {
		req := &ChatCompletionRequest{APIKey: realKey}
		s.forwardModelsRequest(w, r.Context(), req, ch, logger)
		return
	}

	// 4. 读取请求体 JSON
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Log("Error reading request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("User Request Body", string(body), s.config.Global.Log.Debug.MaxContentLength)
	}
	var userReq ChatCompletionRequest
	if err := json.Unmarshal(body, &userReq); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	userReq.APIKey = realKey

	// 5. 选取思考服务（加权随机）
	thinkingSvc := s.getWeightedRandomThinkingService()
	logger.Log("Chosen thinking service: %s (key=%s)", thinkingSvc.Name, logSafeKey(thinkingSvc.APIKey))

	// 6. 判断是否流式请求
	if userReq.Stream {
		// 流式请求
		handler, err := NewStreamHandler(w, thinkingSvc, ch, s.config, logger, userReq.Model)
		if err != nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		if err := handler.Handle(r.Context(), &userReq); err != nil {
			logger.Log("Stream handle error: %v", err)
		}
	} else {
		// 非流式请求：先调用思考服务，再构造最终请求转发给 Channel
		ctxTimeout := ctxWithTimeout(r.Context(), s.config.Global.Thinking.Timeout)
		// (1) 确定思考服务模式
		thinkingMode := determineThinkingMode(thinkingSvc, s.config.Global.Thinking.DefaultMode)
		// (2) 调用思考服务（非流式）
		tResp, err := callThinkingServiceInternal(ctxTimeout, s.config, &userReq, thinkingSvc, thinkingMode, logger)
		if err != nil {
			logger.Log("Thinking service error: %v", err)
			http.Error(w, "Thinking service error", http.StatusInternalServerError)
			return
		}
		// (3) 准备给最终模型的请求（注入系统 prompt）
		finalReq := s.prepareFinalRequest(&userReq, tResp, thinkingMode, logger)
		// (4) 确定 Channel 模式（支持模型级配置）
		channelMode := determineChannelMode(ch, userReq.Model, s.config.Global.Channel.DefaultMode)
		// (5) 转发给最终模型（非流式）
		s.forwardRequestNonStream(w, finalReq, ch, channelMode, logger)
	}
}

// 加权随机选取思考服务
func (s *Server) getWeightedRandomThinkingService() ThinkingService {
	tlist := s.config.ThinkingServices
	if len(tlist) == 0 {
		return ThinkingService{}
	}
	total := 0
	for _, ts := range tlist {
		total += ts.Weight
	}
	if total <= 0 {
		return tlist[0]
	}
	randMu.Lock()
	r := randGen.Intn(total)
	randMu.Unlock()

	sum := 0
	for _, ts := range tlist {
		sum += ts.Weight
		if r < sum {
			return ts
		}
	}
	return tlist[0]
}

// ========== /v1/models 请求转发 ==========

func (s *Server) forwardModelsRequest(w http.ResponseWriter, ctx context.Context,
	req *ChatCompletionRequest, ch Channel, logger *RequestLogger) {

	fullURL := ch.GetFullURL()
	parsed, err := url.Parse(fullURL)
	if err != nil {
		logger.Log("Parse channel url error: %v", err)
		http.Error(w, "Parse channel url error", http.StatusInternalServerError)
		return
	}
	base := parsed.Scheme + "://" + parsed.Host
	modelsURL := strings.TrimSuffix(base, "/") + "/v1/models"

	logger.Log("Forwarding GET /v1/models => %s", modelsURL)

	client, err := createHTTPClient(ch.Proxy, time.Duration(ch.Timeout)*time.Second)
	if err != nil {
		logger.Log("Create client error: %v", err)
		http.Error(w, "Create client error", http.StatusInternalServerError)
		return
	}
	newReq, _ := http.NewRequestWithContext(ctx, "GET", modelsURL, nil)
	newReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	resp, err := client.Do(newReq)
	if err != nil {
		logger.Log("Forward /v1/models error: %v", err)
		http.Error(w, "Forward /v1/models error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log("Read /v1/models resp error: %v", err)
		http.Error(w, "Read /v1/models resp error", http.StatusInternalServerError)
		return
	}
	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("/v1/models Response", string(respBytes), s.config.Global.Log.Debug.MaxContentLength)
	}

	// 回写响应
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBytes)
}

// ========== 非流式：调用思考服务 ==========

func callThinkingServiceInternal(ctx context.Context, config *Config, userReq *ChatCompletionRequest,
	svc ThinkingService, thinkingMode string, logger *RequestLogger) (*ThinkingResponse, error) {

	// 复制请求，修改为调用思考服务
	thinkReq := *userReq
	thinkReq.Model = svc.Model
	thinkReq.APIKey = svc.APIKey

	// 如果模式为 guided，则在消息前插入引导提示
	if thinkingMode == "guided" {
		guidedSys := ChatCompletionMessage{
			Role:    "system",
			Content: "Please provide a detailed reasoning process for your response. Think step by step.",
		}
		thinkReq.Messages = append([]ChatCompletionMessage{guidedSys}, thinkReq.Messages...)
	}

	// 序列化请求
	reqBytes, _ := json.Marshal(thinkReq)
	if config.Global.Log.Debug.PrintRequest {
		logger.LogContent("ThinkingService Request (Non-Stream)", string(reqBytes), config.Global.Log.Debug.MaxContentLength)
	}

	// 发起 HTTP 请求到思考服务
	client, err := createHTTPClient(svc.Proxy, time.Duration(svc.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("create http client: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", svc.GetFullURL(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+svc.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("thinking service do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if config.Global.Log.Debug.PrintResponse {
		logger.LogContent("ThinkingService Response (Non-Stream)", string(respBody), config.Global.Log.Debug.MaxContentLength)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("thinking service status=%d, body=%s", resp.StatusCode, respBody)
	}

	// 解析响应
	var ccr ChatCompletionResponse
	if err := json.Unmarshal(respBody, &ccr); err != nil {
		return nil, fmt.Errorf("unmarshal thinking resp: %w", err)
	}
	if len(ccr.Choices) == 0 {
		return nil, fmt.Errorf("thinking service no choices returned")
	}

	res := &ThinkingResponse{
		Content: ccr.Choices[0].Message.Content,
	}

	// 如果是标准模式且返回中存在 reasoning_content，则视为标准思考
	if thinkingMode == "standard" {
		if ccr.Choices[0].Message.ReasoningContent != nil {
			res.IsStandardMode = true
			raw := ""
			switch v := ccr.Choices[0].Message.ReasoningContent.(type) {
			case string:
				raw = strings.TrimSpace(v)
			case map[string]interface{}:
				b, _ := json.Marshal(v)
				raw = strings.TrimSpace(string(b))
			}
			if raw != "" {
				res.ReasoningContent = raw
				if config.Global.Thinking.ChainPreProcess {
					res.ActualReasoningContent = preprocessReasoningChain(raw)
				} else {
					res.ActualReasoningContent = raw
				}
			}
		}
	}

	// 若未识别为标准，则统一走非标准处理：将 content 作为思考链
	if !res.IsStandardMode {
		res.ActualReasoningContent = res.Content
	}

	return res, nil
}

// ========== 拼接最终请求（非流式） ==========

func (s *Server) prepareFinalRequest(userReq *ChatCompletionRequest, tResp *ThinkingResponse, thinkingMode string, logger *RequestLogger) *ChatCompletionRequest {
	finalReq := *userReq

	// 根据思考服务模式构造系统提示
	var systemPrompt string
	if thinkingMode == "standard" && tResp.IsStandardMode {
		systemPrompt = fmt.Sprintf(
			"Previous reasoning chain:\n%s\nPlease refine your answer accordingly (the chain will not be shown to the user).",
			tResp.ActualReasoningContent,
		)
	} else {
		systemPrompt = fmt.Sprintf(
			"Reasoning process:\n%s\nPlease provide the best answer. (The chain will not be displayed to the user.)",
			tResp.ActualReasoningContent,
		)
	}

	finalReq.Messages = append([]ChatCompletionMessage{
		{Role: "system", Content: systemPrompt},
	}, finalReq.Messages...)

	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Final Enhanced Request -> Channel", finalReq, s.config.Global.Log.Debug.MaxContentLength)
	}
	return &finalReq
}

// ========== 转发给最终模型（非流式） ==========

func (s *Server) forwardRequestNonStream(w http.ResponseWriter, finalReq *ChatCompletionRequest,
	ch Channel, channelMode string, logger *RequestLogger) {

	reqBytes, _ := json.Marshal(finalReq)
	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Forward NonStream => Channel", string(reqBytes), s.config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(ch.Proxy, time.Duration(ch.Timeout)*time.Second)
	if err != nil {
		logger.Log("Create client error: %v", err)
		http.Error(w, "Create client error", http.StatusInternalServerError)
		return
	}
	httpReq, err := http.NewRequest("POST", ch.GetFullURL(), bytes.NewBuffer(reqBytes))
	if err != nil {
		logger.Log("Create request error: %v", err)
		http.Error(w, "Create request error", http.StatusInternalServerError)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+finalReq.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		logger.Log("Do request error: %v", err)
		http.Error(w, "Forward error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log("Read resp body error: %v", err)
		http.Error(w, "Read response error", http.StatusInternalServerError)
		return
	}
	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("Channel NonStream Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
	}

	w.Header().Set("Content-Type", "application/json")
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ========== 流式处理部分 ==========

type StreamHandler struct {
	w              http.ResponseWriter
	flusher        http.Flusher
	thinkingSvc    ThinkingService
	channel        Channel
	config         *Config
	logger         *RequestLogger
	thinkingMode   string
	channelMode    string
	isStdModel     bool   // 是否为标准思考模式
	chainBuf       strings.Builder
	thinkingDone   bool
	userModel      string // 用户请求中指定的 model
}

func NewStreamHandler(w http.ResponseWriter, tSvc ThinkingService, ch Channel,
	cfg *Config, logger *RequestLogger, userModel string) (*StreamHandler, error) {

	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}
	// 根据思考服务和全局默认确定模式
	tMode := determineThinkingMode(tSvc, cfg.Global.Thinking.DefaultMode)
	// 根据 channel 自身模式或全局默认确定 channel 模式（可根据用户请求的 model 判断）
	cMode := determineChannelMode(ch, userModel, cfg.Global.Channel.DefaultMode)
	return &StreamHandler{
		w:             w,
		flusher:       flusher,
		thinkingSvc:   tSvc,
		channel:       ch,
		config:        cfg,
		logger:        logger,
		thinkingMode:  tMode,
		channelMode:   cMode,
		isStdModel:    false,
		thinkingDone:  false,
		userModel:     userModel,
	}, nil
}

// Handle 处理流式请求：先调用思考服务，再调用最终模型
func (h *StreamHandler) Handle(ctx context.Context, userReq *ChatCompletionRequest) error {
	h.w.Header().Set("Content-Type", "text/event-stream")
	h.w.Header().Set("Cache-Control", "no-cache")
	h.w.Header().Set("Connection", "keep-alive")

	// (1) 流式向思考服务请求
	if err := h.streamThinking(ctx, userReq); err != nil {
		return err
	}

	// (2) 检查思考服务是否完整
	if !h.thinkingDone {
		h.logger.Log("Warning: Thinking stream may not have completed fully.")
	}

	// (3) 准备最终请求（注入系统提示）
	finalReq := h.prepareFinalRequest(userReq)
	// (4) 流式向最终模型请求并转发
	return h.streamFinalResponse(ctx, finalReq)
}

// streamThinking 发起流式思考服务请求
func (h *StreamHandler) streamThinking(ctx context.Context, userReq *ChatCompletionRequest) error {
	// 复制请求，设置为流式，并修改为调用思考服务
	reqCopy := *userReq
	reqCopy.Stream = true
	reqCopy.Model = h.thinkingSvc.Model
	reqCopy.APIKey = h.thinkingSvc.APIKey

	// 如果模式为 guided，则在消息前添加引导提示
	if h.thinkingMode == "guided" {
		guidedSys := ChatCompletionMessage{
			Role:    "system",
			Content: "Please provide a detailed reasoning process for your response. Think step by step.",
		}
		reqCopy.Messages = append([]ChatCompletionMessage{guidedSys}, reqCopy.Messages...)
	}

	// 构造请求体
	bodyMap := map[string]interface{}{
		"model":    reqCopy.Model,
		"messages": reqCopy.Messages,
		"stream":   true,
	}
	reqBytes, _ := json.Marshal(bodyMap)
	if h.config.Global.Log.Debug.PrintRequest {
		h.logger.LogContent("ThinkingService Stream Request", string(reqBytes), h.config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(h.thinkingSvc.Proxy, time.Duration(h.thinkingSvc.Timeout)*time.Second)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", h.thinkingSvc.GetFullURL(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+h.thinkingSvc.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("thinking service stream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("thinking service returned %d: %s", resp.StatusCode, b)
	}

	reader := bufio.NewReader(resp.Body)
	var contentBuffer strings.Builder
	contentComplete := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && contentComplete {
				h.thinkingDone = true
				break
			}
			if err == io.EOF {
				break
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			h.thinkingDone = true
			break
		}

		// 解析当前 chunk
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content,omitempty"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason,omitempty"`
			} `json:"choices"`
		}
		if e := json.Unmarshal([]byte(data), &chunk); e != nil {
			h.logger.Log("Parse chunk error: %v", e)
			continue
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		c := chunk.Choices[0]

		// 根据思考模式分别处理
		if h.thinkingMode == "standard" {
			// 如果存在 reasoning_content，则认为是标准模式
			if c.Delta.ReasoningContent != "" {
				h.isStdModel = true
				rcPart := strings.TrimSpace(c.Delta.ReasoningContent)
				if h.config.Global.Thinking.ChainPreProcess {
					rcPart = preprocessReasoningChain(rcPart)
				}
				h.chainBuf.WriteString(rcPart)
				// 在流式+标准模式下，将 reasoning_content 发送给客户端
				sseObj := map[string]interface{}{
					"choices": []map[string]interface{}{
						{"delta": map[string]string{"reasoning_content": rcPart}},
					},
				}
				bs, _ := json.Marshal(sseObj)
				h.w.Write([]byte("data: " + string(bs) + "\n\n"))
				h.flusher.Flush()
			}
			// 同时保存 content
			if c.Delta.Content != "" {
				contentBuffer.WriteString(c.Delta.Content)
			}
		} else {
			// 对于 nonstandard（以及 non-thinking，已归为 nonstandard）模式，将所有返回内容拼接
			if c.Delta.Content != "" {
				contentBuffer.WriteString(c.Delta.Content)
				h.chainBuf.WriteString(c.Delta.Content)
			}
		}

		// 如果检测到 finish_reason，则认为流结束
		if c.FinishReason != nil {
			contentComplete = true
		}
	}

	// 对于非标准模式，统一使用 contentBuffer 作为思考链
	if h.thinkingMode != "standard" {
		h.chainBuf.Reset()
		h.chainBuf.WriteString(contentBuffer.String())
	}

	return nil
}

// prepareFinalRequest 构建最终请求（流式）
func (h *StreamHandler) prepareFinalRequest(userReq *ChatCompletionRequest) *ChatCompletionRequest {
	finalReq := *userReq

	var sysPrompt string
	if h.thinkingMode == "standard" && h.isStdModel {
		sysPrompt = fmt.Sprintf("Previous reasoning chain:\n%s\nPlease refine your answer accordingly (the chain may be displayed).",
			h.chainBuf.String())
	} else {
		sysPrompt = fmt.Sprintf("Reasoning process:\n%s\nPlease provide the best answer. (The chain will not be displayed.)",
			h.chainBuf.String())
	}
	finalReq.Messages = append([]ChatCompletionMessage{
		{Role: "system", Content: sysPrompt},
	}, finalReq.Messages...)

	if h.config.Global.Log.Debug.PrintRequest {
		h.logger.LogContent("Final Channel Stream Request", finalReq, h.config.Global.Log.Debug.MaxContentLength)
	}
	return &finalReq
}

// streamFinalResponse 发起流式请求到最终模型并将响应转发给客户端
func (h *StreamHandler) streamFinalResponse(ctx context.Context, finalReq *ChatCompletionRequest) error {
	// 根据用户请求中指定的 model 确定 Channel 模式
	channelMode := determineChannelMode(h.channel, finalReq.Model, h.config.Global.Channel.DefaultMode)
	h.channelMode = channelMode // 更新

	reqBytes, _ := json.Marshal(finalReq)
	if h.config.Global.Log.Debug.PrintRequest {
		h.logger.LogContent("Channel Stream Request", string(reqBytes), h.config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(h.channel.Proxy, time.Duration(h.channel.Timeout)*time.Second)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", h.channel.GetFullURL(), bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+finalReq.APIKey)

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("final channel returned status=%d, body=%s", resp.StatusCode, b)
	}

	reader := bufio.NewReader(resp.Body)
	timeoutDur := time.Duration(h.config.Global.DefaultTimeout) * time.Second
	timer := time.NewTimer(timeoutDur)
	defer timer.Stop()

	var gotData bool

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if !gotData {
				h.logger.Log("Timeout waiting for final streaming response")
				h.w.Write([]byte("data: {\"error\":\"Timeout waiting for final response\"}\n\n"))
				h.w.Write([]byte("data: [DONE]\n\n"))
				h.flusher.Flush()
				return fmt.Errorf("timeout in final stream")
			}
			// 已收到数据则重置定时器
			timer.Reset(timeoutDur)
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			gotData = true
			timer.Reset(timeoutDur)

			// 根据 channel 模式决定如何转发 SSE
			if h.channelMode == "compatible" {
				// 兼容模式：直接原样转发 SSE 数据
				if line == "data: [DONE]" || line == "data:[DONE]" {
					h.w.Write([]byte("data: [DONE]\n\n"))
					h.flusher.Flush()
					break
				} else {
					h.w.Write([]byte(line + "\n\n"))
					h.flusher.Flush()
				}
			} else {
				// enhanced 模式：可插入额外提示
				if strings.HasPrefix(line, "data: [DONE]") {
					h.w.Write([]byte("data: [DONE]\n\n"))
					h.flusher.Flush()
					break
				}
				h.w.Write([]byte(line + "\n\n"))
				h.flusher.Flush()
			}
		}
	}

	return nil
}

// ========== 工具函数 ==========

// extractRealAPIKey 从 API Key 中提取真实 Key
func extractRealAPIKey(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 3 && (parts[0] == "deep" || parts[0] == "openai") {
		return strings.Join(parts[2:], "-")
	}
	return fullKey
}

// extractChannelID 从 API Key 中提取 channelID
func extractChannelID(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 2 && (parts[0] == "deep" || parts[0] == "openai") {
		return parts[1]
	}
	return "1"
}

// logSafeKey 对 API Key 做脱敏处理
func logSafeKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// createHTTPClient 创建支持代理的 HTTP 客户端
func createHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if proxyURL != "" {
		p, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url: %w", err)
		}
		switch p.Scheme {
		case "http", "https":
			tr.Proxy = http.ProxyURL(p)
		case "socks5":
			dialer, err := proxy.FromURL(p, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create socks5 dialer: %w", err)
			}
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", p.Scheme)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}

// ctxWithTimeout 为请求创建带超时的上下文
func ctxWithTimeout(parent context.Context, seconds int) context.Context {
	if seconds <= 0 {
		return parent
	}
	ctx, _ := context.WithTimeout(parent, time.Duration(seconds)*time.Second)
	return ctx
}

// ========== 配置加载 ==========

func loadConfig() (*Config, error) {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to config file")
	flag.Parse()

	viper.SetConfigType("yaml")
	if cfgPath != "" {
		viper.SetConfigFile(cfgPath)
	} else {
		exe, _ := os.Executable()
		exeDir := filepath.Dir(exe)
		paths := []string{
			filepath.Join(exeDir, "config.yaml"),
			filepath.Join(exeDir, "conf", "config.yaml"),
			"./config.yaml",
			"./conf/config.yaml",
		}
		programData := os.Getenv("PROGRAMDATA")
		if programData != "" {
			paths = append(paths, filepath.Join(programData, "DeepAI", "config.yaml"))
		}
		paths = append(paths, "/etc/deepai/config.yaml")

		for _, p := range paths {
			viper.SetConfigFile(p)
			if err := viper.ReadInConfig(); err == nil {
				break
			}
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config error: %w", err)
	}

	var c Config
	if err := viper.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := validateConfig(&c); err != nil {
		return nil, fmt.Errorf("config invalid: %w", err)
	}

	// 设置默认值
	if c.Global.Thinking.DefaultMode == "" {
		c.Global.Thinking.DefaultMode = "nonstandard"
	}
	if c.Global.Channel.DefaultMode == "" {
		c.Global.Channel.DefaultMode = "compatible"
	}

	return &c, nil
}

// validateConfig 验证配置是否有效
func validateConfig(c *Config) error {
	if len(c.ThinkingServices) == 0 {
		return fmt.Errorf("no thinking_services configured")
	}
	if len(c.Channels) == 0 {
		return fmt.Errorf("no channels configured")
	}
	return nil
}

// ========== main 入口 ==========

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Load config failed: %v", err)
	}
	log.Printf("Using config file: %s", viper.ConfigFileUsed())

	srv := NewServer(cfg)

	// 优雅关闭处理
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server start error: %v", err)
		}
	}()
	log.Println("Server started")

	<-stop
	log.Println("Server stopping...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped gracefully")
}