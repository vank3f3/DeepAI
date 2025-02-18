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

// 配置结构
type Config struct {
	ThinkingServices []ThinkingService  `mapstructure:"thinking_services"`
	Channels         map[string]Channel `mapstructure:"channels"`
	Global           GlobalConfig       `mapstructure:"global"`
}

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
}

func (s *ThinkingService) GetFullURL() string {
	return s.BaseURL + s.APIPath
}

type Channel struct {
	Name    string `mapstructure:"name"`
	BaseURL string `mapstructure:"base_url"`
	APIPath string `mapstructure:"api_path"`
	Timeout int    `mapstructure:"timeout"`
	Proxy   string `mapstructure:"proxy"`
}

func (c *Channel) GetFullURL() string {
	return c.BaseURL + c.APIPath
}

type LogConfig struct {
	Level    string      `mapstructure:"level"`
	Format   string      `mapstructure:"format"`
	Output   string      `mapstructure:"output"`
	FilePath string      `mapstructure:"file_path"`
	Debug    DebugConfig `mapstructure:"debug"`
}

type DebugConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	PrintRequest     bool `mapstructure:"print_request"`
	PrintResponse    bool `mapstructure:"print_response"`
	MaxContentLength int  `mapstructure:"max_content_length"`
}

type ProxyConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Default       string `mapstructure:"default"`
	AllowInsecure bool   `mapstructure:"allow_insecure"`
}

type GlobalConfig struct {
	MaxRetries     int           `mapstructure:"max_retries"`
	DefaultTimeout int           `mapstructure:"default_timeout"`
	ErrorCodes     struct {
		RetryOn []int `mapstructure:"retry_on"`
	} `mapstructure:"error_codes"`
	Log      LogConfig      `mapstructure:"log"`
	Server   ServerConfig   `mapstructure:"server"`
	Proxy    ProxyConfig    `mapstructure:"proxy"`
	Thinking ThinkingConfig `mapstructure:"thinking"`
}

type ServerConfig struct {
	Port         int    `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	IdleTimeout  int    `mapstructure:"idle_timeout"`
}

type ThinkingConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	AddToAllRequests bool `mapstructure:"add_to_all_requests"`
	Timeout          int  `mapstructure:"timeout"`
	// DisplayChain     bool `mapstructure:"display_chain"`      // 不再需要
	ChainPreProcess  bool `mapstructure:"chain_preprocess"`   // 是否预处理思考链
}

// API相关结构
type ChatCompletionRequest struct {
	Model       string                  `json:"model"`
	Messages    []ChatCompletionMessage `json:"messages"`
	Temperature float64                 `json:"temperature,omitempty"`
	MaxTokens   int                     `json:"max_tokens,omitempty"`
	Stream      bool                    `json:"stream,omitempty"`
	APIKey      string                  `json:"-"` // 内部传递，不序列化
}

type ChatCompletionMessage struct {
	Role             string      `json:"role"`
	Content          string      `json:"content"`
	ReasoningContent interface{} `json:"reasoning_content,omitempty"`
}

type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int                   `json:"index"`
	Message      ChatCompletionMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// RequestLogger 用于记录请求日志
type RequestLogger struct {
	RequestID string
	Model     string
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

func (l *RequestLogger) LogContent(contentType string, content interface{}, maxLength int) {
	if !l.config.Global.Log.Debug.Enabled {
		return
	}
	sanitizedContent := sanitizeJSON(content)
	truncatedContent := truncateContent(sanitizedContent, maxLength)
	l.Log("%s Content:\n%s", contentType, truncatedContent)
}

// 工具函数
func truncateContent(content string, maxLength int) string {
	if len(content) <= maxLength {
		return content
	}
	return content[:maxLength] + "... (truncated)"
}

func sanitizeJSON(data interface{}) string {
	sanitized, err := json.Marshal(data)
	if err != nil {
		return "Failed to marshal JSON"
	}
	content := string(sanitized)
	sensitivePattern := `"api_key":\s*"[^"]*"`
	content = regexp.MustCompile(sensitivePattern).ReplaceAllString(content, `"api_key":"****"`)
	return content
}

func extractRealAPIKey(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 3 && (parts[0] == "deep" || parts[0] == "openai") {
		return strings.Join(parts[2:], "-")
	}
	return fullKey
}

func extractChannelID(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 2 && (parts[0] == "deep" || parts[0] == "openai") {
		return parts[1]
	}
	return "1" // 默认渠道
}

func logAPIKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// Server 定义了 HTTP 服务
type Server struct {
	config *Config
	srv    *http.Server
}

// 全局互斥锁和随机数生成器（用于加权随机选择）
var (
	randMu  sync.Mutex
	randGen = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func NewServer(config *Config) *Server {
	return &Server{
		config: config,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleOpenAIRequests)
	mux.HandleFunc("/v1/models", s.handleOpenAIRequests) // 同一个 handler 处理 /v1/models
	mux.HandleFunc("/health", s.handleHealth)

	s.srv = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Global.Server.Host, s.config.Global.Server.Port),
		Handler:      mux,
		ReadTimeout:  time.Duration(s.config.Global.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Global.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.Global.Server.IdleTimeout) * time.Second,
	}

	log.Printf("Server starting on %s\n", s.srv.Addr)
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (s *Server) handleOpenAIRequests(w http.ResponseWriter, r *http.Request) {
	// 判断 Method
	if r.Method != http.MethodPost && r.URL.Path == "/v1/chat/completions" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodGet && r.URL.Path == "/v1/models" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger := NewRequestLogger(s.config)
	fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	apiKey := extractRealAPIKey(fullAPIKey)
	channelID := extractChannelID(fullAPIKey)

	logger.Log("Received request for %s with API Key: %s", r.URL.Path, logAPIKey(fullAPIKey))
	logger.Log("Extracted channel ID: %s", channelID)
	logger.Log("Extracted real API Key: %s", logAPIKey(apiKey))

	targetChannel, ok := s.config.Channels[channelID]
	if !ok {
		http.Error(w, "Invalid channel", http.StatusBadRequest)
		return
	}

	// /v1/models 请求直接转发
	if r.URL.Path == "/v1/models" {
		req := &ChatCompletionRequest{
			APIKey: apiKey,
		}
		logger.Log("Forwarding /v1/models request to channel: %s", targetChannel.Name)
		s.forwardModelsRequest(w, r.Context(), req, targetChannel)
		return
	}

	// 处理 /v1/chat/completions 请求
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Log("Error reading request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Request", string(body), s.config.Global.Log.Debug.MaxContentLength)
	}

	var req ChatCompletionRequest
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.APIKey = apiKey

	// 根据权重随机选一个思考服务
	thinkingService := s.getWeightedRandomThinkingService()
	logger.Log("Using thinking service: %s with API Key: %s", thinkingService.Name, logAPIKey(thinkingService.APIKey))

	// 流式请求
	if req.Stream {
		handler, err := NewStreamHandler(w, thinkingService, targetChannel, s.config)
		if err != nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		if err := handler.HandleRequest(r.Context(), &req); err != nil {
			logger.Log("Stream handler error: %v", err)
			return
		}
	} else {
		// 非流式请求：调用思考服务并处理兼容逻辑
		thinkingResp, err := s.processThinkingContent(r.Context(), &req, thinkingService)
		if err != nil {
			logger.Log("Error processing thinking content: %v", err)
			http.Error(w, "Thinking service error", http.StatusInternalServerError)
			return
		}
		enhancedReq := s.prepareEnhancedRequest(&req, thinkingResp)
		logger.Log("Forwarding enhanced request to channel with API Key: %s", logAPIKey(apiKey))
		s.forwardRequest(w, r.Context(), enhancedReq, targetChannel)
	}
}

// 加权随机选择思考服务（使用互斥锁和 randGen）
func (s *Server) getWeightedRandomThinkingService() ThinkingService {
	thinkingServices := s.config.ThinkingServices
	if len(thinkingServices) == 0 {
		return ThinkingService{}
	}

	totalWeight := 0
	for _, service := range thinkingServices {
		totalWeight += service.Weight
	}

	if totalWeight <= 0 {
		log.Println("Warning: Total weight of thinking services is not positive, using first service as default.")
		return thinkingServices[0]
	}

	randMu.Lock()
	randNum := randGen.Intn(totalWeight)
	randMu.Unlock()

	currentWeightSum := 0
	for _, service := range thinkingServices {
		currentWeightSum += service.Weight
		if randNum < currentWeightSum {
			return service
		}
	}
	log.Println("Warning: Fallback to first thinking service due to unexpected condition in weighted random selection.")
	return thinkingServices[0]
}

// ThinkingResponse 保存思考服务返回的结果, 进行了修改
type ThinkingResponse struct {
	Content                string
	ReasoningContent      string
	ActualReasoningContent string
	IsStandardMode        bool
}

// 非流式处理：解析思考服务响应, 进行了修改
func (s *Server) processThinkingContent(ctx context.Context, req *ChatCompletionRequest,
	thinkingService ThinkingService) (*ThinkingResponse, error) {

	logger := NewRequestLogger(s.config)
	log.Printf("Getting thinking content from service: %s", thinkingService.Name)
	log.Printf("Using thinking service API Key: %s", logAPIKey(thinkingService.APIKey))

	thinkingReq := *req
	thinkingReq.Model = thinkingService.Model
	thinkingReq.APIKey = thinkingService.APIKey

	// 增加系统提示，要求提供详细推理过程
	thinkingPrompt := ChatCompletionMessage{
		Role:    "system",
		Content: "Please provide a detailed reasoning process for your response. Think step by step.",
	}
	thinkingReq.Messages = append([]ChatCompletionMessage{thinkingPrompt}, thinkingReq.Messages...)

	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Thinking Service Request", thinkingReq, s.config.Global.Log.Debug.MaxContentLength)
	}

	jsonData, err := json.Marshal(thinkingReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal thinking request: %v", err)
	}

	client, err := createHTTPClient(thinkingService.Proxy,
		time.Duration(thinkingService.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	request, err := http.NewRequestWithContext(ctx, "POST",
		thinkingService.GetFullURL(),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+thinkingService.APIKey)

	log.Printf("Sending thinking request to: %s", thinkingService.GetFullURL())
	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send thinking request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("Thinking Service Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("thinking service returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var thinkingResp ChatCompletionResponse
	if err := json.NewDecoder(bytes.NewReader(respBody)).Decode(&thinkingResp); err != nil {
		return nil, fmt.Errorf("failed to decode thinking response: %v", err)
	}
	if len(thinkingResp.Choices) == 0 {
		return nil, fmt.Errorf("thinking service returned no choices")
	}

	result := &ThinkingResponse{
		Content: thinkingResp.Choices[0].Message.Content,
	}

    // 尝试解析 reasoning_content
    if thinkingResp.Choices[0].Message.ReasoningContent != nil {
        rawRC := ""
        switch v := thinkingResp.Choices[0].Message.ReasoningContent.(type) {
        case string:
            rawRC = strings.TrimSpace(v)
        case map[string]interface{}:
            if jsonBytes, err := json.Marshal(v); err == nil {
                rawRC = strings.TrimSpace(string(jsonBytes))
            }
        }

        if rawRC != "" {
            result.IsStandardMode = true
            if s.config.Global.Thinking.ChainPreProcess {
                result.ActualReasoningContent = preprocessReasoningChain(rawRC)
            } else {
                result.ActualReasoningContent = rawRC
            }
			// result.ReasoningContent = "思考已完成" // 不需要显示
            return result, nil
        }
    }

    // 非标准模式处理
    result.IsStandardMode = false
    result.ActualReasoningContent = result.Content  // 用于下游API
	result.ReasoningContent = "思考已完成" // 不需要显示
	return result, nil
}

// 构造最终请求：将真实思考链（ActualReasoningContent）拼入系统提示, 保留不变
func (s *Server) prepareEnhancedRequest(originalReq *ChatCompletionRequest,
	thinkingResp *ThinkingResponse) *ChatCompletionRequest {

	logger := NewRequestLogger(s.config)
	enhancedReq := *originalReq

	systemPrompt := fmt.Sprintf(`Based on the following reasoning process:
Reasoning: %s

And the conclusion:
%s

Please provide a response that incorporates this analysis while maintaining natural conversation flow.`,
		thinkingResp.ActualReasoningContent,
		thinkingResp.Content)
	enhancedReq.Messages = append([]ChatCompletionMessage{{
		Role:    "system",
		Content: systemPrompt,
	}}, enhancedReq.Messages...)

	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Enhanced Request", enhancedReq, s.config.Global.Log.Debug.MaxContentLength)
	}

	return &enhancedReq
}

func (s *Server) forwardRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest,
	targetChannel Channel) {

	logger := NewRequestLogger(s.config)
	log.Printf("Forwarding request details:")
	log.Printf("- Channel: %s", targetChannel.Name)
	log.Printf("- URL: %s", targetChannel.GetFullURL())
	log.Printf("- Model: %s", req.Model)
	log.Printf("- Input API Key: %s", logAPIKey(req.APIKey))

	if s.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Forward Request", req, s.config.Global.Log.Debug.MaxContentLength)
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		log.Printf("Error marshaling request: %v", err)
		http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
		return
	}

	client, err := createHTTPClient(targetChannel.Proxy, time.Duration(targetChannel.Timeout)*time.Second)
	if err != nil {
		log.Printf("Error creating HTTP client: %v, Proxy: %s", err, targetChannel.Proxy)
		http.Error(w, fmt.Sprintf("Failed to create HTTP client: %v", err), http.StatusInternalServerError)
		return
	}

	request, err := http.NewRequestWithContext(ctx, "POST",
		targetChannel.GetFullURL(),
		bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+req.APIKey)
	log.Printf("Request headers: %v", maskSensitiveHeaders(request.Header))

	resp, err := client.Do(request)
	if err != nil {
		log.Printf("Error forwarding request: %v", err)
		http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("Forward Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Error response from target: Status: %d, Body: %s", resp.StatusCode, string(respBody))
		http.Error(w, fmt.Sprintf("Target server error: %s", resp.Status), resp.StatusCode)
		return
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (s *Server) forwardModelsRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest, targetChannel Channel) {
	logger := NewRequestLogger(s.config)
	log.Printf("Forwarding /v1/models request details:")
	log.Printf("- Channel: %s", targetChannel.Name)

	fullChatURL := targetChannel.GetFullURL()
	log.Printf("- Full Chat URL: %s", fullChatURL)
	parsedChatURL, err := url.Parse(fullChatURL)
	if err != nil {
		log.Printf("Error parsing chat URL: %v", err)
		http.Error(w, "Failed to parse chat URL", http.StatusInternalServerError)
		return
	}
	baseURL := parsedChatURL.Scheme + "://" + parsedChatURL.Host
	modelsURL := strings.TrimSuffix(baseURL, "/") + "/v1/models"
	log.Printf("- Models URL: %s", modelsURL)
	log.Printf("- Input API Key: %s", logAPIKey(req.APIKey))

	client, err := createHTTPClient(targetChannel.Proxy, time.Duration(targetChannel.Timeout)*time.Second)
	if err != nil {
		log.Printf("Error creating HTTP client: %v, Proxy: %s", err, targetChannel.Proxy)
		http.Error(w, fmt.Sprintf("Failed to create HTTP client: %v", err), http.StatusInternalServerError)
		return
	}

	request, err := http.NewRequestWithContext(ctx, "GET", modelsURL, nil)
	if err != nil {
		log.Printf("Error creating /v1/models request: %v", err)
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	request.Header.Set("Authorization", "Bearer "+req.APIKey)
	log.Printf("Request headers for /v1/models: %v", maskSensitiveHeaders(request.Header))

	resp, err := client.Do(request)
	if err != nil {
		log.Printf("Error forwarding /v1/models request: %v", err)
		http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading /v1/models response body: %v", err)
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}
	if s.config.Global.Log.Debug.PrintResponse {
		logger.LogContent("/v1/models Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Error response from target for /v1/models: Status: %d, Body: %s", resp.StatusCode, string(respBody))
		http.Error(w, fmt.Sprintf("Target server error: %s", resp.Status), resp.StatusCode)
		return
	}
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ThinkingStreamCollector 修改
type ThinkingStreamCollector struct {
	reasoningBuffer strings.Builder
    fullContentBuffer strings.Builder // 新增：用于存储所有内容
	mu              sync.Mutex
	completed       bool
}

func (tc *ThinkingStreamCollector) WriteReasoning(reasoning string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if reasoning != "" {
		tc.reasoningBuffer.WriteString(reasoning)
	}
}

// 新增：WriteFullContent，用于写入所有内容
func (tc *ThinkingStreamCollector) WriteFullContent(content string) {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    if content != "" {
        tc.fullContentBuffer.WriteString(content)
    }
}

func (tc *ThinkingStreamCollector) GetReasoningContent() string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.reasoningBuffer.String()
}

// 新增：GetFullContent，用于获取所有内容
func (tc *ThinkingStreamCollector) GetFullContent() string {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.fullContentBuffer.String()
}

func (tc *ThinkingStreamCollector) SetCompleted() {
	tc.mu.Lock()
	tc.completed = true
	tc.mu.Unlock()
}

func (tc *ThinkingStreamCollector) IsCompleted() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.completed
}

// StreamHandler 处理流式请求
type StreamHandler struct {
	thinkingService ThinkingService
	targetChannel   Channel
	writer          http.ResponseWriter
	flusher         http.Flusher
	config          *Config
}

func NewStreamHandler(w http.ResponseWriter, thinkingService ThinkingService,
	targetChannel Channel, config *Config) (*StreamHandler, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}
	return &StreamHandler{
		thinkingService: thinkingService,
		targetChannel:   targetChannel,
		writer:          w,
		flusher:         flusher,
		config:          config,
	}, nil
}

func (h *StreamHandler) HandleRequest(ctx context.Context, req *ChatCompletionRequest) error {
	logger := NewRequestLogger(h.config)
	h.writer.Header().Set("Content-Type", "text/event-stream")
	h.writer.Header().Set("Cache-Control", "no-cache")
	h.writer.Header().Set("Connection", "keep-alive")

	collector := &ThinkingStreamCollector{}

	// 获取流式思考链
	thinkingContent, err := h.streamThinking(ctx, req, collector, logger)
	if err != nil {
		return fmt.Errorf("thinking stream error: %v", err)
	}
	if !collector.IsCompleted() {
		return fmt.Errorf("thinking stream incomplete")
	}

	// 构造最终请求，将真实思考链附加为系统提示
	finalReq := h.prepareFinalRequest(req, thinkingContent)
	return h.streamFinalResponse(ctx, finalReq, logger)
}

// streamThinking：只负责从思考服务读取流，提取 reasoning_content，并转发所有原始 chunk, 重大修改
func (h *StreamHandler) streamThinking(ctx context.Context, req *ChatCompletionRequest,
    collector *ThinkingStreamCollector, logger *RequestLogger) (string, error) {

    thinkingReq := *req
    thinkingReq.Stream = true
    thinkingReq.Model = h.thinkingService.Model
    thinkingReq.APIKey = h.thinkingService.APIKey

    requestData := map[string]interface{}{
        "model":            thinkingReq.Model,
        "messages":         thinkingReq.Messages,
        "stream":           true,
        "reasoning_effort": "high", // 示例，具体参数根据你的思考服务
        "temperature":      0.7,   // 示例
    }
    jsonData, err := json.Marshal(requestData)
    if err != nil {
        return "", err
    }

    client, err := createHTTPClient(h.thinkingService.Proxy,
        time.Duration(h.thinkingService.Timeout)*time.Second)
    if err != nil {
        return "", fmt.Errorf("failed to create HTTP client: %v", err)
    }

    request, err := http.NewRequestWithContext(ctx, "POST",
        h.thinkingService.GetFullURL(),
        bytes.NewBuffer(jsonData))
    if err != nil {
        return "", err
    }
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+h.thinkingService.APIKey)

    log.Printf("Starting thinking stream from: %s", h.thinkingService.GetFullURL())
    resp, err := client.Do(request)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("thinking service returned status %d: %s", resp.StatusCode, string(body))
	}

	reader := bufio.NewReader(resp.Body)

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
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
			collector.SetCompleted()
			break
		}

		var streamResp struct {
			Choices []struct {
				Delta struct {
					Content          string `json:"content,omitempty"`
					ReasoningContent string `json:"reasoning_content,omitempty"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason,omitempty"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
			log.Printf("Error parsing stream chunk: %v", err)
			continue
		}
		if len(streamResp.Choices) == 0 {
			continue
		}

		choice := streamResp.Choices[0]
		rcPart := strings.TrimSpace(choice.Delta.ReasoningContent)
        ctPart := strings.TrimSpace(choice.Delta.Content) // 获取 content 部分

		// 收集 reasoning_content
		collector.WriteReasoning(rcPart)
        // 收集所有内容
        collector.WriteFullContent(ctPart)
        collector.WriteFullContent(rcPart)


		// 原样转发整个 chunk 给客户端
		sseResponse := fmt.Sprintf("data: %s\n\n", data) // 直接使用原始的 data
		h.writer.Write([]byte(sseResponse))
		h.flusher.Flush()

		if choice.FinishReason != nil {
			collector.SetCompleted()
			break
		}
	}

	// 根据是否有 reasoning_content 来决定返回值
    if collector.GetReasoningContent() != "" {
        return collector.GetReasoningContent(), nil
    }
    return collector.GetFullContent(), nil
}

func (h *StreamHandler) prepareFinalRequest(originalReq *ChatCompletionRequest,
	thinkingContent string) *ChatCompletionRequest {
	finalReq := *originalReq
	thinkingMsg := ChatCompletionMessage{
		Role:    "system",
		Content: fmt.Sprintf("Previous thinking process:\n%s\nPlease consider the above thinking process in your response.", thinkingContent),
	}
	finalReq.Messages = append([]ChatCompletionMessage{thinkingMsg}, finalReq.Messages...)
	return &finalReq
}

func (h *StreamHandler) streamFinalResponse(ctx context.Context, req *ChatCompletionRequest,
	logger *RequestLogger) error {

	if h.config.Global.Log.Debug.PrintRequest {
		logger.LogContent("Final Stream Request", req, h.config.Global.Log.Debug.MaxContentLength)
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	client, err := createHTTPClient(h.targetChannel.Proxy, time.Duration(h.targetChannel.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %v", err)
	}

	request, err := http.NewRequestWithContext(ctx, "POST",
		h.targetChannel.GetFullURL(),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+req.APIKey)
	log.Printf("Starting final response stream from: %s", h.targetChannel.GetFullURL())
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("target service returned status %d: %s", resp.StatusCode, string(body))
	}
	reader := bufio.NewReader(resp.Body)
	var lastProcessedLine string
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
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
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			h.writer.Write([]byte("data: [DONE]\n\n"))
			h.flusher.Flush()
			break
		}
		if data == lastProcessedLine {
			continue
		}
		lastProcessedLine = data
		var jsonCheck map[string]interface{}
		if err := json.Unmarshal([]byte(data), &jsonCheck); err != nil {
			log.Printf("Invalid JSON in response: %v", err)
			continue
		}
		sseResponse := fmt.Sprintf("data: %s\n\n", data)
		h.writer.Write([]byte(sseResponse))
		h.flusher.Flush()
		if h.config.Global.Log.Debug.PrintResponse {
			logger.LogContent("Final Stream Chunk", string(sseResponse), h.config.Global.Log.Debug.MaxContentLength)
		}
	}
	return nil
}

// 思考链预处理函数(保留之前的实现)
func preprocessReasoningChain(chain string) string {
	// 实现思考链的预处理逻辑，例如：
	// - 移除非必要的提示文本
	// - 格式化思考步骤
	// - 提取关键推理过程
	// 这里需要根据实际的思考链格式来实现

	// 示例实现
	lines := strings.Split(chain, "\n")
	var processed []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 排除辅助性提示
		if strings.HasPrefix(line, "Assistant:") ||
			strings.HasPrefix(line, "System:") ||
			strings.HasPrefix(line, "Note:") {
			continue
		}
		if line != "" {
			processed = append(processed, line)
		}
	}

	return strings.Join(processed, "\n")
}

// createHTTPClient 创建支持代理的 HTTP 客户端, 保留不变
func createHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
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
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		switch parsedURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(parsedURL)
		case "socks5":
			dialer, err := proxy.FromURL(parsedURL, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
			}
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", parsedURL.Scheme)
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

func maskSensitiveHeaders(headers http.Header) http.Header {
	masked := make(http.Header)
	for k, v := range headers {
		if k == "Authorization" {
			masked[k] = []string{"Bearer ****"}
		} else {
			masked[k] = v
		}
	}
	return masked
}

func loadConfig() (*Config, error) {
	var configFile string
	flag.StringVar(&configFile, "config", "", "path to config file")
	flag.Parse()
	viper.SetConfigType("yaml")
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		ex, err := os.Executable()
		if err != nil {
			return nil, err
		}
		exePath := filepath.Dir(ex)
		defaultPaths := []string{
			filepath.Join(exePath, "config.yaml"),
			filepath.Join(exePath, "conf", "config.yaml"),
			"./config.yaml",
			"./conf/config.yaml",
		}
		if os.PathSeparator == '\\' {
			programData := os.Getenv("PROGRAMDATA")
			if programData != "" {
				defaultPaths = append(defaultPaths, filepath.Join(programData, "DeepAI", "config.yaml"))
			}
		} else {
			defaultPaths = append(defaultPaths, "/etc/deepai/config.yaml")
		}
		for _, path := range defaultPaths {
			viper.AddConfigPath(filepath.Dir(path))
			if strings.Contains(path, ".yaml") {
				viper.SetConfigName(strings.TrimSuffix(filepath.Base(path), ".yaml"))
			}
		}
	}
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}
	return &config, nil
}

func validateConfig(config *Config) error {
	if len(config.ThinkingServices) == 0 {
		return fmt.Errorf("no thinking services configured")
	}
	if len(config.Channels) == 0 {
		return fmt.Errorf("no channels configured")
	}
	for _, service := range config.ThinkingServices {
		if service.BaseURL == "" {
			return fmt.Errorf("thinking service %s has no base URL", service.Name)
		}
		if service.APIKey == "" {
			return fmt.Errorf("thinking service %s has no API key", service.Name)
		}
		if service.Timeout <= 0 {
			return fmt.Errorf("thinking service %s has invalid timeout", service.Name)
		}
		if service.Model == "" {
			return fmt.Errorf("thinking service %s has no model specified", service.Name)
		}
	}
	for id, channel := range config.Channels {
		if channel.BaseURL == "" {
			return fmt.Errorf("channel %s has no base URL", id)
		}
		if channel.Timeout <= 0 {
			return fmt.Errorf("channel %s has invalid timeout", id)
		}
	}
	if config.Global.DefaultTimeout <= 0 {
		return fmt.Errorf("invalid global default timeout")
	}
	if config.Global.Server.Port <= 0 {
		return fmt.Errorf("invalid server port")
	}
	return nil
}

func main() {
	// 设置日志格式：包含日期、时间（精确到微秒）、文件名和行号
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Using config file: %s", viper.ConfigFileUsed())
	server := NewServer(config)
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()
	log.Printf("Server started successfully")
	<-done
	log.Print("Server stopping...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Print("Server stopped")
}