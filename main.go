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
	Mode    string `mapstructure:"mode"` // 新增：思考模式 (auto, standard, nonstandard, guided)
}

func (s *ThinkingService) GetFullURL() string {
	return s.BaseURL + s.APIPath
}

// Channel 后端 LLM 通道配置
type Channel struct {
	Name        string        `mapstructure:"name"`
	BaseURL     string        `mapstructure:"base_url"`
	APIPath     string        `mapstructure:"api_path"`
	Timeout     int           `mapstructure:"timeout"`
	Proxy       string        `mapstructure:"proxy"`
	Mode        string        `mapstructure:"mode"` // 新增：通道模式 (compatible, enhanced)
	ModelConfig []ModelConfig `mapstructure:"model_config"` // 新增：模型特定配置
}

type ModelConfig struct {
	ModelPattern string `mapstructure:"model_pattern"`
	Mode         string `mapstructure:"mode"`
}

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
	Channel  ChannelConfig  `mapstructure:"channel"` // 新增：通道全局配置
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
	ChainPreProcess  bool   `mapstructure:"chain_preprocess"` // 可选：是否对思考链做预处理
	DefaultMode      string `mapstructure:"default_mode"`      // 新增：默认思考模式
}

// ChannelConfig 通道相关配置
type ChannelConfig struct {
	DefaultMode string `mapstructure:"default_mode"` // 新增：默认通道模式
}

// LogConfig 日志配置
type LogConfig struct {
	Level    string    `mapstructure:"level"`
	Format   string    `mapstructure:"format"`
	Output   string    `mapstructure:"output"`
	FilePath string    `mapstructure:"file_path"`
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

// ThinkingResponse 用于保存“思考服务”的输出
type ThinkingResponse struct {
	Content                string // 思考服务的最终回答文本
	ReasoningContent       string // 原始 reasoning_content 或者空
	ActualReasoningContent string // 真正要给后端模型用的思考链
	IsStandardMode         bool   // 是否属于标准思考模型(有 reasoning_content)
}

// 对思考链做预处理（可选）
func preprocessReasoningChain(chain string) string {
	lines := strings.Split(chain, "\n")
	var processed []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		// 这里也可以过滤一些特定前缀
		if strings.HasPrefix(ln, "Note:") {
			continue
		}
		processed = append(processed, ln)
	}
	return strings.Join(processed, "\n")
}

// ============ 模式判断 ============

func determineThinkingMode(svc ThinkingService, model string, config *Config) string {
	// 1. 检查服务特定配置
	if svc.Mode != "" && svc.Mode != "auto" {
		return svc.Mode
	}

	// 2. 尝试自动识别 (恢复 0.3.x 的逻辑)
	if isStandardThinkingResponse(svc, config) {
		return "standard"
	}

	// 3. 回退到全局默认
	return config.Global.Thinking.DefaultMode
}

// isStandardThinkingResponse 辅助函数：检查响应是否为标准思考模型格式
func isStandardThinkingResponse(svc ThinkingService, config *Config) bool {
	// 创建一个临时的请求上下文和日志记录器
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logger := NewRequestLogger(config)

	// 构造一个简单的测试请求
	testReq := ChatCompletionRequest{
		Model: svc.Model,
		Messages: []ChatCompletionMessage{
			{Role: "user", Content: "Placeholder question"},
		},
	}

	// 调用 callThinkingServiceInternal（非流式版本）
	tResp, err := callThinkingServiceInternal(ctx, config, &testReq, svc, svc.Mode, logger)
	if err != nil {
		log.Printf("Error during thinking mode detection: %v", err)
		return false // 无法确定，返回 false
	}

	// 判断返回的是不是标准模型
	return tResp.IsStandardMode
}

func determineChannelMode(ch Channel, model string, config *Config) string {
	// 1. 检查模型特定配置
	for _, mc := range ch.ModelConfig {
		if matched, _ := regexp.MatchString(mc.ModelPattern, model); matched {
			return mc.Mode
		}
	}

	// 2. 检查通道级配置
	if ch.Mode != "" {
		return ch.Mode
	}

	// 3. 回退到全局默认
	return config.Global.Channel.DefaultMode
}

// ============ 服务器主体 ============

type Server struct {
	config *Config
	srv    *http.Server
}

// 全局随机
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

// 核心处理入口
func (s *Server) handleOpenAIRequests(w http.ResponseWriter, r *http.Request) {
	// 判定方法
	if r.URL.Path == "/v1/chat/completions" && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/v1/models" && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := NewRequestLogger(s.config)

	// 1. 获取 Authorization Bearer
	fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	realKey := extractRealAPIKey(fullAPIKey)
	channelID := extractChannelID(fullAPIKey)

	logger.Log("Incoming request: %s  (APIKey=%s)  channelID=%s",
		r.URL.Path, logSafeKey(fullAPIKey), channelID)

	// 2. 找到对应Channel
	ch, ok := s.config.Channels[channelID]
	if !ok {
		http.Error(w, "Invalid channel", http.StatusBadRequest)
		return
	}

	// 如果是 /v1/models，直接转发 GET
	if r.URL.Path == "/v1/models" {
		req := &ChatCompletionRequest{APIKey: realKey}
		s.forwardModelsRequest(w, r.Context(), req, ch, logger)
		return
	}

	// 3. 读取body解析 ChatCompletionRequest
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

	// 4. 根据权重选一个思考服务
	thinkingSvc := s.getWeightedRandomThinkingService()
	logger.Log("Chosen thinking service: %s (key=%s)",
		thinkingSvc.Name, logSafeKey(thinkingSvc.APIKey))

	// 分流：是否是 stream
	if userReq.Stream {
		// 流式处理
		handler, err := NewStreamHandler(w, thinkingSvc, ch, s.config, logger)
		if err != nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		if err := handler.Handle(r.Context(), &userReq); err != nil {
			logger.Log("Stream handler error: %v", err)
			return
		}
	} else {
		// 非流式处理
		thinkingMode := determineThinkingMode(thinkingSvc, userReq.Model, s.config)
		tResp, err := s.callThinkingService(ctxWithTimeout(r.Context(), s.config.Global.Thinking.Timeout), &userReq, thinkingSvc, thinkingMode, logger)
		if err != nil {
			logger.Log("Thinking service error: %v", err)
			http.Error(w, "Thinking service error", http.StatusInternalServerError)
			return
		}

		// 拼装对最终模型的请求
		finalReq := s.prepareFinalRequest(&userReq, tResp, thinkingMode, logger)
		channelMode := determineChannelMode(ch, userReq.Model, s.config)
		s.forwardRequestNonStream(w, finalReq, ch, channelMode, logger)
	}
}

// ========== 加权随机选思考服务 ==========

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

// ========== /v1/models 处理（只GET） ==========

func (s *Server) forwardModelsRequest(w http.ResponseWriter, ctx context.Context,
	req *ChatCompletionRequest, ch Channel, logger *RequestLogger) {

	// 构造 /v1/models 的URL
	fullURL := ch.GetFullURL()
	parsed, err := url.Parse(fullURL)
	if err != nil {
		logger.Log("Parse channel url error: %v", err)
		http.Error(w, "parse channel url error", http.StatusInternalServerError)
		return
	}
	base := parsed.Scheme + "://" + parsed.Host
	modelsURL := strings.TrimSuffix(base, "/") + "/v1/models"

	logger.Log("Forwarding GET /v1/models => %s", modelsURL)

	client, err := createHTTPClient(ch.Proxy, time.Duration(ch.Timeout)*time.Second)
	if err != nil {
		logger.Log("Create client error: %v", err)
		http.Error(w, "create http client error", http.StatusInternalServerError)
		return
	}
	newReq, _ := http.NewRequestWithContext(ctx, "GET", modelsURL, nil)
	newReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	resp, err := client.Do(newReq)
	if err != nil {
		logger.Log("forward /v1/models error: %v", err)
		http.Error(w, "forward /v1/models error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log("read /v1/models resp error: %v", err)
		http.Error(w, "read /v1/models resp error", http.StatusInternalServerError)
		return
	}

	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("/v1/models Response", string(respBytes), s.config.Global.Log.Debug.MaxContentLength)
	}

	// 原样返回
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBytes)
}

// ========== 非流式：调用思考服务 ==========

// callThinkingServiceInternal 为包级辅助函数，供非流式调用思考服务使用
func callThinkingServiceInternal(ctx context.Context, config *Config, userReq *ChatCompletionRequest,
	svc ThinkingService, thinkingMode string, logger *RequestLogger) (*ThinkingResponse, error) {

	// 准备请求体
	thinkReq := *userReq
	thinkReq.Model = svc.Model
	thinkReq.APIKey = svc.APIKey
	// 如果是 "guided" 模式，添加 system 消息
	if thinkingMode == "guided" {
		guidedPrompt := ChatCompletionMessage{
			Role:    "system",
			Content: "Please provide a detailed reasoning process for your response. Think step by step.",
		}
		thinkReq.Messages = append([]ChatCompletionMessage{guidedPrompt}, thinkReq.Messages...)
	}

	reqBody, _ := json.Marshal(thinkReq)
	if config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Thinking Service Request (Non-Stream)", string(reqBody), config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(svc.Proxy, time.Duration(svc.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("create http client: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", svc.GetFullURL(), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+svc.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("thinking service do: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if config.Global.Log.Debug.PrintResponse {
		logger.LogContent("Thinking Service Response (Non-Stream)", string(respBytes), config.Global.Log.Debug.MaxContentLength)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("thinking service status=%d, body=%s", resp.StatusCode, respBytes)
	}

	var ccr ChatCompletionResponse
	if err := json.Unmarshal(respBytes, &ccr); err != nil {
		return nil, fmt.Errorf("unmarshal thinking resp: %w", err)
	}
	if len(ccr.Choices) == 0 {
		return nil, fmt.Errorf("thinking service no choices returned")
	}

	tResp := &ThinkingResponse{
		Content: ccr.Choices[0].Message.Content,
	}

	// 根据 thinkingMode 处理
	switch thinkingMode {
	case "standard":
		if ccr.Choices[0].Message.ReasoningContent != nil {
			raw := ""
			switch v := ccr.Choices[0].Message.ReasoningContent.(type) {
			case string:
				raw = strings.TrimSpace(v)
			case map[string]interface{}:
				if b, e := json.Marshal(v); e == nil {
					raw = strings.TrimSpace(string(b))
				}
			}
			if raw != "" {
				tResp.IsStandardMode = true
				if config.Global.Thinking.ChainPreProcess {
					tResp.ActualReasoningContent = preprocessReasoningChain(raw)
				} else {
					tResp.ActualReasoningContent = raw
				}
				tResp.ReasoningContent = raw // 仅留作调试
			}
		}
	case "nonstandard", "guided":
		tResp.ActualReasoningContent = tResp.Content // 非标准模式，直接以返回的content作为思考链
	}

	return tResp, nil
}

// Server 方法，包装调用辅助函数
func (s *Server) callThinkingService(ctx context.Context, userReq *ChatCompletionRequest,
	svc ThinkingService, thinkingMode string, logger *RequestLogger) (*ThinkingResponse, error) {
	return callThinkingServiceInternal(ctx, s.config, userReq, svc, thinkingMode, logger)
}

// ========== 拼装对最终模型的请求 ==========

func (s *Server) prepareFinalRequest(userReq *ChatCompletionRequest, tResp *ThinkingResponse, thinkingMode string, logger *RequestLogger) *ChatCompletionRequest {
	finalReq := *userReq
	var systemPrompt string

	// 根据 thinkingMode 和 tResp.IsStandardMode 构建提示
	if thinkingMode == "standard" && tResp.IsStandardMode {
		systemPrompt = fmt.Sprintf("Previous reasoning chain:\n%s\nPlease refine answer accordingly.", tResp.ActualReasoningContent)
	} else {
		systemPrompt = fmt.Sprintf("Reasoning process:\n%s\n\nPlease provide the best answer.", tResp.ActualReasoningContent)
	}

	finalReq.Messages = append([]ChatCompletionMessage{
		{Role: "system", Content: systemPrompt},
	}, finalReq.Messages...)

	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Enhanced Final Request", finalReq, s.config.Global.Log.Debug.MaxContentLength)
	}
	return &finalReq
}

// ========== 非流式 => 最终模型 ==========

func (s *Server) forwardRequestNonStream(w http.ResponseWriter, finalReq *ChatCompletionRequest,
	ch Channel, channelMode string, logger *RequestLogger) {

	reqBody, _ := json.Marshal(finalReq)
	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Forward NonStream => Channel", string(reqBody), s.config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(ch.Proxy, time.Duration(ch.Timeout)*time.Second)
	if err != nil {
		logger.Log("Create client error: %v", err)
		http.Error(w, "create http client error", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", ch.GetFullURL(), bytes.NewBuffer(reqBody))
	if err != nil {
		logger.Log("Create request error: %v", err)
		http.Error(w, "create request error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+finalReq.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		logger.Log("Do request error: %v", err)
		http.Error(w, "forward error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log("Read resp body error: %v", err)
		http.Error(w, "read resp error", http.StatusInternalServerError)
		return
	}

	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("Channel NonStream Response", string(respBytes), s.config.Global.Log.Debug.MaxContentLength)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		w.WriteHeader(resp.StatusCode)
		w.Write(respBytes)
		return
	}

	// 把后端头也拷贝过去
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBytes)
}

// ========== 流式处理器 ==========

type StreamHandler struct {
	w                http.ResponseWriter
	flusher          http.Flusher
	thinkingSvc      ThinkingService
	channel          Channel
	config           *Config
	logger           *RequestLogger
	isStdModel       bool   // 是否标准思考模型
	chainBuf         strings.Builder
	thinkingComplete bool   // 思考过程是否已完整结束
	thinkingMode     string // 思考模式
	channelMode      string // 通道模式
}

// NewStreamHandler 创建 StreamHandler
func NewStreamHandler(w http.ResponseWriter, tSvc ThinkingService, ch Channel, cfg *Config, logger *RequestLogger) (*StreamHandler, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}
	thinkingMode := determineThinkingMode(tSvc, "", cfg) // 这里传入 "" 作为 model，因为此时还没有 userReq
	channelMode := determineChannelMode(ch, "", cfg)      // 同上

	return &StreamHandler{
		w:                w,
		flusher:          flusher,
		thinkingSvc:      tSvc,
		channel:          ch,
		config:           cfg,
		logger:           logger,
		thinkingComplete: false,
		thinkingMode:     thinkingMode,
		channelMode:      channelMode,
	}, nil
}

// Handle 处理流式请求
func (h *StreamHandler) Handle(ctx context.Context, userReq *ChatCompletionRequest) error {
	h.w.Header().Set("Content-Type", "text/event-stream")
	h.w.Header().Set("Cache-Control", "no-cache")
	h.w.Header().Set("Connection", "keep-alive")

	// 1. 先向思考服务发起流式请求
	if err := h.streamThinking(ctx, userReq); err != nil {
		return err
	}

	// 2. 检查思考过程是否完整
	if !h.thinkingComplete {
		h.logger.Log("Warning: Thinking process might not have completed fully.")
	}

	// 3. 准备最终请求
	finalReq := h.prepareFinalRequest(userReq)

	// 4. 向最终模型发起流式请求
	return h.streamFinalResponse(ctx, finalReq)
}

// streamThinking 向思考服务发起流式请求
func (h *StreamHandler) streamThinking(ctx context.Context, userReq *ChatCompletionRequest) error {
	reqCopy := *userReq
	reqCopy.Stream = true
	reqCopy.Model = h.thinkingSvc.Model
	reqCopy.APIKey = h.thinkingSvc.APIKey
	// 如果是 "guided" 模式，添加 system 消息
	if h.thinkingMode == "guided" {
		guidedPrompt := ChatCompletionMessage{
			Role:    "system",
			Content: "Please provide a detailed reasoning process for your response. Think step by step.",
		}
		reqCopy.Messages = append([]ChatCompletionMessage{guidedPrompt}, reqCopy.Messages...)
	}

	bodyMap := map[string]interface{}{
		"model":    reqCopy.Model,
		"messages": reqCopy.Messages,
		"stream":   true,
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	if h.config.Global.Log.Debug.PrintRequest {
		h.logger.LogContent("ThinkingService Stream Request", string(bodyBytes), h.config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(h.thinkingSvc.Proxy, time.Duration(h.thinkingSvc.Timeout)*time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", h.thinkingSvc.GetFullURL(), bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.thinkingSvc.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("thinking service stream request fail: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("thinking service returned %d: %s", resp.StatusCode, b)
	}

	reader := bufio.NewReader(resp.Body)
	contentComplete := false // 新增：content 是否已完整接收
	var contentBuffer strings.Builder // 用于存储思考内容

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && contentComplete {
				h.thinkingComplete = true // 标记思考过程完整结束
				break
			}
			if err == io.EOF {
				break
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			// 收到 [DONE] 也认为是正常结束
			h.thinkingComplete = true
			break
		}

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

		// 根据 thinkingMode 处理
		switch h.thinkingMode {
		case "standard":
			// 处理 reasoning_content
			if c.Delta.ReasoningContent != "" {
				h.isStdModel = true // 标记为标准模型
				rcPart := strings.TrimSpace(c.Delta.ReasoningContent)
				if h.config.Global.Thinking.ChainPreProcess {
					rcPart = preprocessReasoningChain(rcPart)
				}
				h.chainBuf.WriteString(rcPart)
				contentBuffer.WriteString(rcPart)
				// 实时发送 reasoning_content
				sseObj := map[string]interface{}{
					"choices": []map[string]interface{}{
						{
							"delta": map[string]string{
								"reasoning_content": rcPart,
							},
						},
					},
				}
				b, _ := json.Marshal(sseObj)
				sseLine := "data: " + string(b) + "\n\n"
				_, _ = h.w.Write([]byte(sseLine))
				h.flusher.Flush()
			}

			// 处理 content (无论是否标准模型)
			if c.Delta.Content != "" {
				contentBuffer.WriteString(c.Delta.Content)
			}
		case "nonstandard", "guided":
			if c.Delta.Content != "" {
				contentBuffer.WriteString(c.Delta.Content)
				h.chainBuf.WriteString(c.Delta.Content)
			}
		}

		// 如果有 finish_reason，则标记 content 已完整接收
		if c.FinishReason != nil {
			contentComplete = true
		}
	}

	// 循环结束后，将累积的 content 写入 chainBuf (非标准模型)
	if h.thinkingMode == "nonstandard" || h.thinkingMode == "guided" {
		h.chainBuf.Reset()
		h.chainBuf.WriteString(contentBuffer.String())
	}

	return nil
}

// prepareFinalRequest 准备最终请求
func (h *StreamHandler) prepareFinalRequest(userReq *ChatCompletionRequest) *ChatCompletionRequest {
	finalReq := *userReq

	var systemPrompt string
	if h.thinkingMode == "standard" && h.isStdModel {
		systemPrompt = fmt.Sprintf("Previous reasoning chain:\n%s\nPlease refine answer accordingly.", h.chainBuf.String())
	} else {
		systemPrompt = fmt.Sprintf("Reasoning process:\n%s\n\nPlease provide the best answer.", h.chainBuf.String())
	}

	finalReq.Messages = append([]ChatCompletionMessage{
		{Role: "system", Content: systemPrompt},
	}, finalReq.Messages...)

	if h.config.Global.Log.Debug.PrintRequest {
		h.logger.LogContent("Final Channel Stream Request", finalReq, h.config.Global.Log.Debug.MaxContentLength)
	}

	return &finalReq
}

// streamFinalResponse 向最终模型发起流式请求 (最终改进版)
func (h *StreamHandler) streamFinalResponse(ctx context.Context, finalReq *ChatCompletionRequest) error {
	reqBody, _ := json.Marshal(finalReq)
	if h.config.Global.Log.Debug.PrintRequest {
		h.logger.LogContent("Final Channel Stream Request", string(reqBody), h.config.Global.Log.Debug.MaxContentLength)
	}

	client, err := createHTTPClient(h.channel.Proxy, time.Duration(h.channel.Timeout)*time.Second)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", h.channel.GetFullURL(), bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+finalReq.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("final channel status=%d, body=%s", resp.StatusCode, b)
	}

	reader := bufio.NewReader(resp.Body)
	timeoutDuration := time.Duration(h.config.Global.DefaultTimeout) * time.Second
	timer := time.NewTimer(timeoutDuration)
	defer timer.Stop()

	// 根据 channelMode 选择不同的处理方式
	if h.channelMode == "compatible" {
		// 兼容模式：直接转发
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				h.logger.Log("Timeout waiting for final response")
				return fmt.Errorf("timeout in compatible mode")
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
				h.w.Write([]byte(line + "\n"))
				h.flusher.Flush()
				timer.Reset(timeoutDuration)
			}
		}
	} else { // 增强模式
		if h.isStdModel {
			transitionMsg := "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"\\n\\n[思考完成，准备生成回答]\\n\\n\"}}]}\n\n"
			h.w.Write([]byte(transitionMsg))
			h.flusher.Flush()
			time.Sleep(200 * time.Millisecond)
		}

		startMsg := "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n"
		h.w.Write([]byte(startMsg))
		h.flusher.Flush()

		receivedData := false

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				if !receivedData {
					h.logger.Log("Timeout waiting for final response")
					h.w.Write([]byte("data: {\"error\":\"Timeout waiting for response\"}\n\n"))
					h.w.Write([]byte("data: [DONE]\n\n"))
					h.flusher.Flush()
					return fmt.Errorf("timeout waiting for final response")
				}
				return nil
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
				if line == "data:[DONE]\n" || line == "data: [DONE]\n" {
					h.w.Write([]byte("data: [DONE]\n\n"))
				} else {
					h.w.Write([]byte(line))
					if !strings.HasSuffix(line, "\n") {
						h.w.Write([]byte("\n"))
					}
					if !strings.HasSuffix(line, "\n\n") {
						h.w.Write([]byte("\n"))
					}
				}
				h.flusher.Flush()
				receivedData = true
				timer.Reset(timeoutDuration)
			}
		}
	}

	return nil
}

// ========== 其他公共函数 ==========

// 从header拿Bearer
func extractRealAPIKey(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	// 例：Bearer deep-1-sk-xxxx => parts = [deep, 1, sk, xxxx...]
	if len(parts) >= 3 && (parts[0] == "deep" || parts[0] == "openai") {
		return strings.Join(parts[2:], "-")
	}
	return fullKey
}

// 从header拿channel id
func extractChannelID(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 2 && (parts[0] == "deep" || parts[0] == "openai") {
		return parts[1]
	}
	return "1"
}

// 日志里安全化显示Key
func logSafeKey(k string) string {
	if len(k) <= 8 {
		return k
	}
	return k[:4] + "..." + k[len(k)-4:]
}

func maskSensitiveHeaders(h http.Header) http.Header {
	masked := make(http.Header)
	for k, vs := range h {
		if strings.EqualFold(k, "Authorization") {
			masked[k] = []string{"Bearer ****"}
		} else {
			masked[k] = vs
		}
	}
	return masked
}

// 创建支持代理的HTTP client
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
		pu, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url: %w", err)
		}
		switch pu.Scheme {
		case "http", "https":
			tr.Proxy = http.ProxyURL(pu)
		case "socks5":
			dialer, err := proxy.FromURL(pu, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("new socks5 dialer: %w", err)
			}
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", pu.Scheme)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}

func ctxWithTimeout(parent context.Context, seconds int) context.Context {
	if seconds <= 0 {
		return parent
	}
	ctx, _ := context.WithTimeout(parent, time.Duration(seconds)*time.Second)
	return ctx
}

// ========== 加载配置 ==========

func loadConfig() (*Config, error) {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to config file")
	flag.Parse()

	viper.SetConfigType("yaml")

	if cfgPath != "" {
		viper.SetConfigFile(cfgPath)
	} else {
		// 依次尝试从若干默认路径读取
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
	// 设置默认值（如果未在配置文件中指定）
	if c.Global.Thinking.DefaultMode == "" {
		c.Global.Thinking.DefaultMode = "auto"
	}
	if c.Global.Channel.DefaultMode == "" {
		c.Global.Channel.DefaultMode = "compatible"
	}

	return &c, nil
}

func validateConfig(c *Config) error {
	if len(c.ThinkingServices) == 0 {
		return fmt.Errorf("no thinking_services configured")
	}
	if len(c.Channels) == 0 {
		return fmt.Errorf("no channels configured")
	}
	for _, ts := range c.ThinkingServices {
		if ts.Mode != "" && ts.Mode != "auto" && ts.Mode != "standard" && ts.Mode != "nonstandard" && ts.Mode != "guided" {
			return fmt.Errorf("invalid thinking service mode: %s", ts.Mode)
		}
	}
	for _, ch := range c.Channels {
		if ch.Mode != "" && ch.Mode != "compatible" && ch.Mode != "enhanced" {
			return fmt.Errorf("invalid channel mode: %s", ch.Mode)
		}
		for _, mc := range ch.ModelConfig {
			if mc.Mode != "compatible" && mc.Mode != "enhanced" {
				return fmt.Errorf("invalid model config mode: %s", mc.Mode)
			}
		}
	}
	return nil
}

// ========== main 入口 ==========

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Load config fail: %v", err)
	}
	log.Printf("Using config: %s", viper.ConfigFileUsed())

	srv := NewServer(cfg)

	// 优雅关闭
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