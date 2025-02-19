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
    ThinkingServices []ThinkingService       `mapstructure:"thinking_services"`
    Channels         map[string]Channel      `mapstructure:"channels"`
    Global           GlobalConfig            `mapstructure:"global"`
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
    Mode    string `mapstructure:"mode"` // 新增：思考模式，支持"standard"和"full"
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
    Log         LogConfig    `mapstructure:"log"`
    Server      ServerConfig `mapstructure:"server"`
    Proxy       ProxyConfig  `mapstructure:"proxy"`
    ConfigPaths []string     `mapstructure:"config_paths"`
    Thinking    ThinkingConfig `mapstructure:"thinking"`
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
}

// API相关结构
type ChatCompletionRequest struct {
    Model       string                  `json:"model"`
    Messages    []ChatCompletionMessage `json:"messages"`
    Temperature float64                 `json:"temperature,omitempty"`
    MaxTokens   int                     `json:"max_tokens,omitempty"`
    Stream      bool                    `json:"stream,omitempty"`
    APIKey      string                  `json:"-"` // 用于内部传递，不序列化
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

// RequestLogger 结构体
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

// Server 结构体
type Server struct {
    config *Config
    srv    *http.Server
}

// —— 新增一个全局的互斥锁 + rand.Rand，用于加权随机 —— //
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
    mux.HandleFunc("/v1/models", s.handleOpenAIRequests) // 使用同一个 handler 处理 /v1/models
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

    // 如果是 /v1/models 请求
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

    // 如果启用了请求内容打印
    if s.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("Request", string(body), s.config.Global.Log.Debug.MaxContentLength)
    }

    var req ChatCompletionRequest
    if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    req.APIKey = apiKey // 赋值解析后的 APIKey

    // 根据权重随机选一个思考服务
    thinkingService := s.getWeightedRandomThinkingService()
    logger.Log("Using thinking service: %s (Mode: %s) with API Key: %s",
        thinkingService.Name, thinkingService.Mode, logAPIKey(thinkingService.APIKey))

    // 如果是流式请求
    if req.Stream {
        handler, err := NewStreamHandler(w, thinkingService, targetChannel, s.config)
        if err != nil {
            http.Error(w, "Streaming not supported", http.StatusInternalServerError)
            return
        }

        if err := handler.HandleRequest(r.Context(), &req); err != nil {
            logger.Log("Stream handler error: %v", err)
            // 如果出错，可以在这里再写点错误信息给客户端
            return
        }
    } else {
        // 普通（非流式）请求
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

// —— 改造成使用私有的 randGen 和互斥锁 —— //
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
            // 如果没有设置模式，默认为标准模式
            if service.Mode == "" {
                service.Mode = "standard"
            }
            return service
        }
    }

    log.Println("Warning: Fallback to first thinking service due to unexpected condition in weighted random selection.")
    // 确保默认模式
    if thinkingServices[0].Mode == "" {
        thinkingServices[0].Mode = "standard"
    }
    return thinkingServices[0]
}

type ThinkingResponse struct {
    Content          string
    ReasoningContent string
    Confidence       float64
}

func (s *Server) processThinkingContent(ctx context.Context, req *ChatCompletionRequest,
    thinkingService ThinkingService) (*ThinkingResponse, error) {

    logger := NewRequestLogger(s.config)

    // 确保模式有效值
    if thinkingService.Mode == "" {
        thinkingService.Mode = "standard"
    }

    log.Printf("Getting thinking content from service: %s (Mode: %s)", 
        thinkingService.Name, thinkingService.Mode)
    log.Printf("Using thinking service API Key: %s", logAPIKey(thinkingService.APIKey))

    thinkingReq := *req
    thinkingReq.Model = thinkingService.Model
    thinkingReq.APIKey = thinkingService.APIKey

    // 根据模式设置不同的系统提示
    var thinkingPrompt ChatCompletionMessage
    if thinkingService.Mode == "full" {
        thinkingPrompt = ChatCompletionMessage{
            Role:    "system",
            Content: "Provide a detailed step-by-step analysis of the question. Your entire response will be used as reasoning and won't be shown to the user directly.",
        }
    } else { // 标准模式
        thinkingPrompt = ChatCompletionMessage{
            Role:    "system",
            Content: "Please provide a detailed reasoning process for your response. Think step by step.",
        }
    }
    
    thinkingReq.Messages = append([]ChatCompletionMessage{thinkingPrompt}, thinkingReq.Messages...)

    // 记录思考服务请求
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

    // 记录思考服务响应
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

    // 根据模式处理响应
    result := &ThinkingResponse{}
    if thinkingService.Mode == "full" {
        // 全量模式：将整个content作为reasoning_content使用
        result.ReasoningContent = thinkingResp.Choices[0].Message.Content
        result.Content = "Based on the above detailed analysis." // 简单结论
    } else {
        // 标准模式：保持现有处理逻辑
        result.Content = thinkingResp.Choices[0].Message.Content

        if thinkingResp.Choices[0].Message.ReasoningContent != nil {
            switch v := thinkingResp.Choices[0].Message.ReasoningContent.(type) {
            case string:
                result.ReasoningContent = v
            case map[string]interface{}:
                if jsonBytes, err := json.Marshal(v); err == nil {
                    result.ReasoningContent = string(jsonBytes)
                } else {
                    log.Printf("Warning: Failed to marshal reasoning content: %v", err)
                }
            default:
                log.Printf("Warning: Unexpected reasoning_content type: %T", v)
            }
        }

        // 标准模式的后备处理
        if result.ReasoningContent == "" {
            result.ReasoningContent = result.Content
            result.Content = "Based on the above reasoning."
        }
    }

    log.Printf("Processed thinking content (Mode: %s):", thinkingService.Mode)
    log.Printf("- Content length: %d", len(result.Content))
    log.Printf("- Reasoning content length: %d", len(result.ReasoningContent))

    return result, nil
}

func (s *Server) prepareEnhancedRequest(originalReq *ChatCompletionRequest,
    thinkingResp *ThinkingResponse) *ChatCompletionRequest {

    logger := NewRequestLogger(s.config)

    enhancedReq := *originalReq

    systemPrompt := fmt.Sprintf(`Based on the following reasoning process:
Reasoning: %s

And the conclusion:
%s

Please provide a response that incorporates this analysis while maintaining natural conversation flow.`,
        thinkingResp.ReasoningContent,
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

    // 打印请求内容
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

    // 记录响应内容
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

    request, err := http.NewRequestWithContext(ctx, "GET",
        modelsURL,
        nil)
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

// ThinkingStreamCollector 用于收集和处理思考链的流式输出
type ThinkingStreamCollector struct {
    buffer    strings.Builder
    mu        sync.Mutex
    completed bool
}

func (tc *ThinkingStreamCollector) Write(p []byte) (n int, err error) {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.buffer.Write(p)
}

func (tc *ThinkingStreamCollector) GetContent() string {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    return tc.buffer.String()
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

    // 确保模式有效值
    if thinkingService.Mode == "" {
        thinkingService.Mode = "standard"
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

    // 先从思考服务获取流式推理内容
    thinkingContent, err := h.streamThinking(ctx, req, collector, logger)
    if err != nil {
        return fmt.Errorf("thinking stream error: %v", err)
    }

    if !collector.IsCompleted() {
        return fmt.Errorf("thinking stream incomplete")
    }

    // 拿到思考内容后，构造最终请求，继续流式返回
    finalReq := h.prepareFinalRequest(req, thinkingContent)
    return h.streamFinalResponse(ctx, finalReq, logger)
}

func (h *StreamHandler) streamThinking(ctx context.Context, req *ChatCompletionRequest,
    collector *ThinkingStreamCollector, logger *RequestLogger) (string, error) {

    thinkingReq := *req
    thinkingReq.Stream = true
    thinkingReq.Model = h.thinkingService.Model
    thinkingReq.APIKey = h.thinkingService.APIKey

    // 构建请求数据，根据模式调整
    var systemPrompt string
    if h.thinkingService.Mode == "full" {
        systemPrompt = "Provide a detailed step-by-step analysis of the question. Your entire response will be used as reasoning and won't be shown to the user directly."
    } else {
        systemPrompt = "Please provide a detailed reasoning process for your response. Think step by step."
    }
    
    // 添加system消息
    messages := append([]ChatCompletionMessage{
        {Role: "system", Content: systemPrompt},
    }, thinkingReq.Messages...)

    requestData := map[string]interface{}{
        "model":            thinkingReq.Model,
        "messages":         messages,
        "stream":           true,
        "reasoning_effort": "high", // 对支持的模型
        "temperature":      0.7,
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

    log.Printf("Starting thinking stream from: %s (Mode: %s)", 
        h.thinkingService.GetFullURL(), h.thinkingService.Mode)

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
    var reasoningContent strings.Builder
    var lastLine string

    for {
        // —— 可选：在循环里检查 ctx 是否已取消 —— //
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
        if line == "" || line == lastLine {
            continue
        }
        lastLine = line

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
                    Content           string `json:"content"`
                    ReasoningContent  string `json:"reasoning_content,omitempty"`
                } `json:"delta"`
                FinishReason *string `json:"finish_reason,omitempty"`
            } `json:"choices"`
        }

        if err := json.Unmarshal([]byte(data), &streamResp); err != nil {
            log.Printf("Error parsing stream chunk: %v", err)
            continue
        }

        if len(streamResp.Choices) > 0 {
            choice := streamResp.Choices[0]
            
            // 根据不同模式处理流式内容
            if h.thinkingService.Mode == "full" {
                // 全量模式：只关注content字段
                if choice.Delta.Content != "" {
                    reasoningContent.WriteString(choice.Delta.Content)
                    collector.Write([]byte(choice.Delta.Content))
                }
            } else {
                // 标准模式：处理reasoning_content
                if choice.Delta.ReasoningContent != "" {
                    reasoningContent.WriteString(choice.Delta.ReasoningContent)
                    collector.Write([]byte(choice.Delta.ReasoningContent))
                }

                // 处理普通content
                if choice.Delta.Content != "" {
                    collector.Write([]byte(choice.Delta.Content))
                }
            }

            // 转发 SSE 响应给客户端 (只转发本次 chunk 的数据)
            sseData := map[string]interface{}{
                "choices": []map[string]interface{}{
                    {
                        "delta": map[string]interface{}{
                            "content":           choice.Delta.Content,
                            "reasoning_content": choice.Delta.ReasoningContent,
                        },
                        "finish_reason": choice.FinishReason,
                    },
                },
            }
            sseBytes, _ := json.Marshal(sseData)
            sseResponse := fmt.Sprintf("data: %s\n\n", string(sseBytes))

            h.writer.Write([]byte(sseResponse))
            h.flusher.Flush()

            if h.config.Global.Log.Debug.PrintResponse {
                logger.LogContent("Thinking Stream Chunk", streamResp,
                    h.config.Global.Log.Debug.MaxContentLength)
            }

            // 如果后端提示结束
            if choice.FinishReason != nil {
                collector.SetCompleted()
                break
            }
        }
    }

    return reasoningContent.String(), nil
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

    client, err := createHTTPClient(h.targetChannel.Proxy,
        time.Duration(h.targetChannel.Timeout)*time.Second)
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
        // —— 可选：在循环里检查 ctx 是否已取消 —— //
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

        // 避免重复行
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
            logger.LogContent("Final Stream Chunk", string(sseResponse),
                h.config.Global.Log.Debug.MaxContentLength)
        }
    }

    return nil
}

func (h *StreamHandler) prepareFinalRequest(originalReq *ChatCompletionRequest,
    thinkingContent string) *ChatCompletionRequest {
    finalReq := *originalReq

    var systemPrompt string
    if h.thinkingService.Mode == "full" {
        systemPrompt = fmt.Sprintf("Consider the following detailed analysis (not shown to user):\n%s\n\nProvide a clear, concise response that incorporates insights from this analysis while maintaining natural conversation flow.", thinkingContent)
    } else {
        systemPrompt = fmt.Sprintf("Previous thinking process:\n%s\nPlease consider the above thinking process in your response.", thinkingContent)
    }

    finalReq.Messages = append([]ChatCompletionMessage{{
        Role:    "system",
        Content: systemPrompt,
    }}, finalReq.Messages...)
    
    return &finalReq
}