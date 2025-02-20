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

// ---------------------- 配置结构 ----------------------

type Config struct {
    ThinkingServices []ThinkingService  `mapstructure:"thinking_services"`
    Channels         map[string]Channel `mapstructure:"channels"`
    Global           GlobalConfig       `mapstructure:"global"`
}

type ThinkingService struct {
    ID                     int      `mapstructure:"id"`
    Name                   string   `mapstructure:"name"`
    Model                  string   `mapstructure:"model"`
    BaseURL                string   `mapstructure:"base_url"`
    APIPath                string   `mapstructure:"api_path"`
    APIKey                 string   `mapstructure:"api_key"`
    Timeout                int      `mapstructure:"timeout"`
    Retry                  int      `mapstructure:"retry"`
    Weight                 int      `mapstructure:"weight"`
    Proxy                  string   `mapstructure:"proxy"`
    Mode                   string   `mapstructure:"mode"`  // "standard" or "full"
    ReasoningEffort        string   `mapstructure:"reasoning_effort"`
    ReasoningFormat        string   `mapstructure:"reasoning_format"`
    Temperature            *float64 `mapstructure:"temperature"`
    ForceStopDeepThinking  bool     `mapstructure:"force_stop_deep_thinking"` // 新增
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
    MaxRetries     int            `mapstructure:"max_retries"`
    DefaultTimeout int            `mapstructure:"default_timeout"`
    ErrorCodes     struct {
        RetryOn []int `mapstructure:"retry_on"`
    } `mapstructure:"error_codes"`
    Log         LogConfig      `mapstructure:"log"`
    Server      ServerConfig   `mapstructure:"server"`
    Proxy       ProxyConfig    `mapstructure:"proxy"`
    ConfigPaths []string       `mapstructure:"config_paths"`
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

// ---------------------- API 相关结构 ----------------------

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

// ---------------------- 日志工具 ----------------------

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

// ---- 工具函数 ----

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

// ---------------------- Server 结构 ----------------------

type Server struct {
    config *Config
    srv    *http.Server
}

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
    mux.HandleFunc("/v1/models", s.handleOpenAIRequests)
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

    if r.URL.Path == "/v1/models" {
        // /v1/models => GET
        if r.Method != http.MethodGet {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }
        req := &ChatCompletionRequest{APIKey: apiKey}
        s.forwardModelsRequest(w, r.Context(), req, targetChannel)
        return
    }

    // /v1/chat/completions => POST
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

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

    thinkingService := s.getWeightedRandomThinkingService()
    logger.Log("Using thinking service: %s with API Key: %s", thinkingService.Name, logAPIKey(thinkingService.APIKey))

    // 分流：看 stream
    if req.Stream {
        handler, err := NewStreamHandler(w, thinkingService, targetChannel, s.config)
        if err != nil {
            http.Error(w, "Streaming not supported", http.StatusInternalServerError)
            return
        }
        if err := handler.HandleRequest(r.Context(), &req); err != nil {
            logger.Log("Stream handler error: %v", err)
        }
    } else {
        // 非流式: 先拿思考服务 -> 再转发给目标
        thinkingResp, err := s.processThinkingContent(r.Context(), &req, thinkingService)
        if err != nil {
            logger.Log("Error processing thinking content: %v", err)
            http.Error(w, "Thinking service error: "+err.Error(), http.StatusInternalServerError)
            return
        }
        enhancedReq := s.prepareEnhancedRequest(&req, thinkingResp, thinkingService)
        s.forwardRequest(w, r.Context(), enhancedReq, targetChannel)
    }
}

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
    currentSum := 0
    for _, svc := range thinkingServices {
        currentSum += svc.Weight
        if randNum < currentSum {
            return svc
        }
    }
    return thinkingServices[0]
}

// ---------------------- 非流式处理思考服务 ----------------------

type ThinkingResponse struct {
    Content          string
    ReasoningContent string
}

func (s *Server) processThinkingContent(ctx context.Context, req *ChatCompletionRequest, svc ThinkingService) (*ThinkingResponse, error) {
    logger := NewRequestLogger(s.config)
    log.Printf("Getting thinking content from service: %s (mode=%s)", svc.Name, svc.Mode)

    thinkingReq := *req
    thinkingReq.Model = svc.Model
    thinkingReq.APIKey = svc.APIKey

    // 构造 system 消息
    var systemPrompt string
    if svc.Mode == "full" {
        systemPrompt = "Provide a detailed step-by-step analysis of the question. Your entire response will be used as reasoning and won't be shown to the user directly."
    } else {
        systemPrompt = "Please provide a detailed reasoning process for your response. Think step by step."
    }
    thinkingReq.Messages = append([]ChatCompletionMessage{
        {Role: "system", Content: systemPrompt},
    }, thinkingReq.Messages...)

    temperature := 0.7
    if svc.Temperature != nil {
        temperature = *svc.Temperature
    }
    payload := map[string]interface{}{
        "model":       svc.Model,
        "messages":    thinkingReq.Messages,
        "stream":      false,
        "temperature": temperature,
    }
    if isValidReasoningEffort(svc.ReasoningEffort) {
        payload["reasoning_effort"] = svc.ReasoningEffort
    }
    if isValidReasoningFormat(svc.ReasoningFormat) {
        payload["reasoning_format"] = svc.ReasoningFormat
    }

    if s.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("Thinking Service Request", payload, s.config.Global.Log.Debug.MaxContentLength)
    }

    jsonData, err := json.Marshal(payload)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal: %v", err)
    }
    client, err := createHTTPClient(svc.Proxy, time.Duration(svc.Timeout)*time.Second)
    if err != nil {
        return nil, fmt.Errorf("failed to create http client: %v", err)
    }
    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, svc.GetFullURL(), bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %v", err)
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+svc.APIKey)

    resp, err := client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("thinking service request error: %v", err)
    }
    defer resp.Body.Close()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("read body error: %v", err)
    }
    if s.config.Global.Log.Debug.PrintResponse {
        logger.LogContent("Thinking Service Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
    }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("thinking service returned %d: %s", resp.StatusCode, string(respBody))
    }

    var thinkingResp ChatCompletionResponse
    if err := json.Unmarshal(respBody, &thinkingResp); err != nil {
        return nil, fmt.Errorf("unmarshal error: %v", err)
    }
    if len(thinkingResp.Choices) == 0 {
        return nil, fmt.Errorf("thinking service no choices")
    }
    choice := thinkingResp.Choices[0]

    result := &ThinkingResponse{}

    if svc.Mode == "full" {
        // full模式：把 content 当成 reasoning
        result.ReasoningContent = choice.Message.Content
        result.Content = "Based on the above detailed analysis."
    } else {
        // standard模式：优先看 reasoning_content
        if choice.Message.ReasoningContent != nil {
            switch v := choice.Message.ReasoningContent.(type) {
            case string:
                result.ReasoningContent = v
            case map[string]interface{}:
                if j, err := json.Marshal(v); err == nil {
                    result.ReasoningContent = string(j)
                }
            }
        }
        if result.ReasoningContent == "" {
            result.ReasoningContent = choice.Message.Content
        }
        result.Content = "Based on the above reasoning."
    }
    return result, nil
}

// 拼接给目标通道的请求
func (s *Server) prepareEnhancedRequest(originalReq *ChatCompletionRequest, thinkingResp *ThinkingResponse, svc ThinkingService) *ChatCompletionRequest {
    newReq := *originalReq
    var systemPrompt string
    if svc.Mode == "full" {
        systemPrompt = fmt.Sprintf(`Consider the following detailed analysis (not shown to user):
%s

Provide a clear, concise response that incorporates insights from this analysis.`, thinkingResp.ReasoningContent)
    } else {
        systemPrompt = fmt.Sprintf(`Previous thinking process:
%s
Please consider the above thinking process in your response.`, thinkingResp.ReasoningContent)
    }
    newReq.Messages = append([]ChatCompletionMessage{
        {Role: "system", Content: systemPrompt},
    }, newReq.Messages...)

    return &newReq
}

func (s *Server) forwardRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest, channel Channel) {
    logger := NewRequestLogger(s.config)
    if s.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("Forward Request", req, s.config.Global.Log.Debug.MaxContentLength)
    }
    jsonData, err := json.Marshal(req)
    if err != nil {
        http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
        return
    }

    client, err := createHTTPClient(channel.Proxy, time.Duration(channel.Timeout)*time.Second)
    if err != nil {
        http.Error(w, fmt.Sprintf("create http client error: %v", err), http.StatusInternalServerError)
        return
    }

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, channel.GetFullURL(), bytes.NewBuffer(jsonData))
    if err != nil {
        http.Error(w, "Failed to create request", http.StatusInternalServerError)
        return
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

    resp, err := client.Do(httpReq)
    if err != nil {
        http.Error(w, "Forward request error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Failed to read response", http.StatusInternalServerError)
        return
    }
    if s.config.Global.Log.Debug.PrintResponse {
        logger.LogContent("Forward Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
    }
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        http.Error(w, fmt.Sprintf("Target server error: %s", resp.Status), resp.StatusCode)
        return
    }

    for k, vals := range resp.Header {
        for _, v := range vals {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    w.Write(respBody)
}

// 转发 /v1/models
func (s *Server) forwardModelsRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest, targetChannel Channel) {
    logger := NewRequestLogger(s.config)
    if s.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("/v1/models Request", req, s.config.Global.Log.Debug.MaxContentLength)
    }
    fullChatURL := targetChannel.GetFullURL()
    parsedURL, err := url.Parse(fullChatURL)
    if err != nil {
        http.Error(w, "parse url error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    baseURL := parsedURL.Scheme + "://" + parsedURL.Host
    modelsURL := strings.TrimSuffix(baseURL, "/") + "/v1/models"

    client, err := createHTTPClient(targetChannel.Proxy, time.Duration(targetChannel.Timeout)*time.Second)
    if err != nil {
        http.Error(w, "create client error: "+err.Error(), http.StatusInternalServerError)
        return
    }

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
    if err != nil {
        http.Error(w, "create request error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

    resp, err := client.Do(httpReq)
    if err != nil {
        http.Error(w, "forward /v1/models error: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "read /v1/models response error", http.StatusInternalServerError)
        return
    }
    if s.config.Global.Log.Debug.PrintResponse {
        logger.LogContent("/v1/models Response", string(respBody), s.config.Global.Log.Debug.MaxContentLength)
    }
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        http.Error(w, fmt.Sprintf("Target server error: %s", resp.Status), resp.StatusCode)
        return
    }

    for k, vals := range resp.Header {
        for _, v := range vals {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    w.Write(respBody)
}

// ---------------------- 流式处理 ----------------------

// 在流式场景下，我们需要把思考服务的 SSE + 最终Channel的 SSE **合并**给用户，
// 并在其中把思考服务的 reasoning_content 也“原样”转发，让客户端能解析。
type StreamHandler struct {
    thinkingService ThinkingService
    targetChannel   Channel
    writer          http.ResponseWriter
    flusher         http.Flusher
    config          *Config
}

func NewStreamHandler(w http.ResponseWriter, thinkingService ThinkingService, targetChannel Channel, config *Config) (*StreamHandler, error) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        return nil, fmt.Errorf("streaming not supported by this writer")
    }
    return &StreamHandler{
        thinkingService: thinkingService,
        targetChannel:   targetChannel,
        writer:          w,
        flusher:         flusher,
        config:          config,
    }, nil
}

// 在这个结构里我们存放 收集到的思考链，用于后续请求目标Channel时做“隐藏提示”。
type collectedReasoningBuffer struct {
    builder strings.Builder
    mode    string
}

func (cb *collectedReasoningBuffer) appendReasoning(text string) {
    cb.builder.WriteString(text)
}

func (cb *collectedReasoningBuffer) getReasoning() string {
    return cb.builder.String()
}

// HandleRequest：
// 1) 打开流式 SSE 给客户端
// 2) 连接思考服务，边读取 SSE 边原样转发
// 3) 收集 reasoning_content (以及content, 如果模式=full) 用于后续给目标Channel
// 4) 当思考服务结束(或强���停止)后，发起目标Channel请求，将其 SSE 也转发给用户
func (h *StreamHandler) HandleRequest(ctx context.Context, req *ChatCompletionRequest) error {
    // 先设置 SSE 头
    h.writer.Header().Set("Content-Type", "text/event-stream")
    h.writer.Header().Set("Cache-Control", "no-cache")
    h.writer.Header().Set("Connection", "keep-alive")

    logger := NewRequestLogger(h.config)

    // Step 1: 先获取并转发思考服务SSE
    reasonBuf := &collectedReasoningBuffer{mode: h.thinkingService.Mode}
    if err := h.streamThinkingService(ctx, req, reasonBuf, logger); err != nil {
        return err
    }

    // Step 2: 用收集到的思考链，生成对目标Channel的最终请求
    finalReq := h.prepareFinalRequest(req, reasonBuf.getReasoning())

    // Step 3: 对目标Channel发起SSE请求，并转发给客户端
    if err := h.streamFinalChannel(ctx, finalReq, logger); err != nil {
        return err
    }

    return nil
}

// streamThinkingService：连接到思考服务（流式），把它的 SSE chunk 原样给前端，
// 并额外将 reasoning_content (标准模式只收集 reasoning_content；全量模式收集 content+reasoning_content) 保存到 reasonBuf。
func (h *StreamHandler) streamThinkingService(ctx context.Context, req *ChatCompletionRequest, reasonBuf *collectedReasoningBuffer, logger *RequestLogger) error {
    // 构造思考服务的请求体
    thinkingReq := *req
    thinkingReq.Model = h.thinkingService.Model
    thinkingReq.APIKey = h.thinkingService.APIKey

    var systemPrompt string
    if h.thinkingService.Mode == "full" {
        systemPrompt = "Provide a detailed step-by-step analysis of the question. Your entire response will be used as reasoning and won't be shown to the user directly."
    } else {
        systemPrompt = "Please provide a detailed reasoning process for your response. Think step by step."
    }
    messages := append([]ChatCompletionMessage{
        {Role: "system", Content: systemPrompt},
    }, thinkingReq.Messages...)

    temperature := 0.7
    if h.thinkingService.Temperature != nil {
        temperature = *h.thinkingService.Temperature
    }
    bodyMap := map[string]interface{}{
        "model":       thinkingReq.Model,
        "messages":    messages,
        "temperature": temperature,
        "stream":      true,
    }
    if isValidReasoningEffort(h.thinkingService.ReasoningEffort) {
        bodyMap["reasoning_effort"] = h.thinkingService.ReasoningEffort
    }
    if isValidReasoningFormat(h.thinkingService.ReasoningFormat) {
        bodyMap["reasoning_format"] = h.thinkingService.ReasoningFormat
    }

    jsonData, err := json.Marshal(bodyMap)
    if err != nil {
        return err
    }

    client, err := createHTTPClient(h.thinkingService.Proxy, time.Duration(h.thinkingService.Timeout)*time.Second)
    if err != nil {
        return err
    }

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.thinkingService.GetFullURL(), bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+h.thinkingService.APIKey)

    log.Printf("ThinkingService SSE => %s (mode=%s, forcedStop=%v)", h.thinkingService.GetFullURL(), h.thinkingService.Mode, h.thinkingService.ForceStopDeepThinking)
    resp, err := client.Do(httpReq)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("thinking service status=%d, body=%s", resp.StatusCode, string(b))
    }

    reader := bufio.NewReader(resp.Body)
    var lastLine string
    forceStop := false

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
        if line == "" || line == lastLine {
            continue
        }
        lastLine = line

        if !strings.HasPrefix(line, "data: ") {
            continue
        }
        dataPart := strings.TrimPrefix(line, "data: ")
        if dataPart == "[DONE]" {
            // 思考服务自己结束了
            // 这里不想让 SSE 整体结束，所以改成 THNKING_DONE
            donePayload := "data: [THINKING_DONE]\n\n"
            h.writer.Write([]byte(donePayload))
            h.flusher.Flush()
            break
        }

        // 把原始 data 解析一下，收集 reasoning_content
        var chunk struct {
            Choices []struct {
                Delta struct {
                    Content          string `json:"content,omitempty"`
                    ReasoningContent string `json:"reasoning_content,omitempty"`
                } `json:"delta"`
                FinishReason *string `json:"finish_reason,omitempty"`
            } `json:"choices"`
        }
        if err := json.Unmarshal([]byte(dataPart), &chunk); err != nil {
            // 如果解析失败，就还是直接原样转发
            h.writer.Write([]byte("data: " + dataPart + "\n\n"))
            h.flusher.Flush()
            continue
        }

        if len(chunk.Choices) > 0 {
            c := chunk.Choices[0]
            if h.config.Global.Log.Debug.PrintResponse {
                logger.LogContent("Thinking SSE chunk", chunk, h.config.Global.Log.Debug.MaxContentLength)
            }

            // 收集 reasoning_content
            if h.thinkingService.Mode == "full" {
                // full => content + reasoning_content 都加到隐藏链
                if c.Delta.ReasoningContent != "" {
                    reasonBuf.appendReasoning(c.Delta.ReasoningContent)
                }
                if c.Delta.Content != "" {
                    reasonBuf.appendReasoning(c.Delta.Content)
                }
            } else {
                // standard => 只收集 reasoning_content
                if c.Delta.ReasoningContent != "" {
                    reasonBuf.appendReasoning(c.Delta.ReasoningContent)
                }
                // 如果 forceStopDeepThinking 开启，而且出现了 content => 强制停止
                if c.Delta.Content != "" && h.thinkingService.ForceStopDeepThinking {
                    forceStop = true
                }
            }

            // 如果 finishReason 不为空，也表示思考服务结束
            if c.FinishReason != nil && *c.FinishReason != "" {
                // 这里也改成 [THINKING_DONE]
                donePayload := "data: [THINKING_DONE]\n\n"
                h.writer.Write([]byte(donePayload))
                h.flusher.Flush()
                break
            }
        }

        // 如果出现 content 并 forceStop = true，就截断
        if forceStop {
            // 这里也通知前端一下
            donePayload := "data: [THINKING_DONE]\n\n"
            h.writer.Write([]byte(donePayload))
            h.flusher.Flush()
            _ = resp.Body.Close()
            break
        }

        // **关键**：这里把「思考服务」的 SSE chunk 原样转发给用户，
        // 这样用户就会收到 reasoning_content 以及 content
        // 不过当你 rename [DONE] => [THINKING_DONE] 后，原始 data=... 里就不会出现 [DONE] 了
        // 但 chunk 内部还是 {"choices":[{"delta":{...}}]} 的结构
        forwardLine := "data: " + dataPart + "\n\n"
        h.writer.Write([]byte(forwardLine))
        h.flusher.Flush()
    }

    // 读空剩余部分
    io.Copy(io.Discard, reader)

    return nil
}

func (h *StreamHandler) prepareFinalRequest(originalReq *ChatCompletionRequest, reasoningCollected string) *ChatCompletionRequest {
    req := *originalReq
    var systemPrompt string
    if h.thinkingService.Mode == "full" {
        systemPrompt = fmt.Sprintf(
            `Consider the following detailed analysis (not shown to user):
%s

Provide a clear, concise response that incorporates insights from this analysis.`,
            reasoningCollected,
        )
    } else {
        systemPrompt = fmt.Sprintf(
            `Previous thinking process:
%s
Please consider the above thinking process in your response.`,
            reasoningCollected,
        )
    }
    req.Messages = append([]ChatCompletionMessage{
        {Role: "system", Content: systemPrompt},
    }, req.Messages...)
    return &req
}

// streamFinalChannel => 请求目标Channel的流式 SSE，并原样转发给前端
func (h *StreamHandler) streamFinalChannel(ctx context.Context, req *ChatCompletionRequest, logger *RequestLogger) error {
    if h.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("Final Request to Channel", req, h.config.Global.Log.Debug.MaxContentLength)
    }

    jsonData, err := json.Marshal(req)
    if err != nil {
        return err
    }
    client, err := createHTTPClient(h.targetChannel.Proxy, time.Duration(h.targetChannel.Timeout)*time.Second)
    if err != nil {
        return err
    }
    httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.targetChannel.GetFullURL(), bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }
    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

    resp, err := client.Do(httpReq)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("target channel status=%d, body=%s", resp.StatusCode, string(b))
    }

    reader := bufio.NewReader(resp.Body)
    var lastLine string

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
        if line == "" || line == lastLine {
            continue
        }
        lastLine = line

        if !strings.HasPrefix(line, "data: ") {
            continue
        }
        data := strings.TrimPrefix(line, "data: ")
        if data == "[DONE]" {
            // 目标Channel的 [DONE] 就是真正结束
            doneLine := "data: [DONE]\n\n"
            h.writer.Write([]byte(doneLine))
            h.flusher.Flush()
            break
        }

        // 原样转发
        forwardLine := "data: " + data + "\n\n"
        h.writer.Write([]byte(forwardLine))
        h.flusher.Flush()

        if h.config.Global.Log.Debug.PrintResponse {
            logger.LogContent("Channel SSE chunk", forwardLine, h.config.Global.Log.Debug.MaxContentLength)
        }
    }

    // 读空
    io.Copy(io.Discard, reader)

    return nil
}

// ---------------------- HTTP Client 工具 ----------------------

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
    for k, vals := range headers {
        if strings.ToLower(k) == "authorization" {
            masked[k] = []string{"Bearer ****"}
        } else {
            masked[k] = vals
        }
    }
    return masked
}

func isValidReasoningEffort(effort string) bool {
    switch strings.ToLower(effort) {
    case "low", "medium", "high":
        return true
    }
    return false
}
func isValidReasoningFormat(format string) bool {
    switch strings.ToLower(format) {
    case "parsed", "raw", "hidden":
        return true
    }
    return false
}

// ---------------------- 配置加载与验证 ----------------------

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
        for _, p := range defaultPaths {
            viper.AddConfigPath(filepath.Dir(p))
            if strings.Contains(p, ".yaml") {
                viper.SetConfigName(strings.TrimSuffix(filepath.Base(p), ".yaml"))
            }
        }
    }

    if err := viper.ReadInConfig(); err != nil {
        return nil, fmt.Errorf("failed to read config: %v", err)
    }

    var cfg Config
    if err := viper.Unmarshal(&cfg); err != nil {
        return nil, fmt.Errorf("unmarshal config error: %v", err)
    }
    if err := validateConfig(&cfg); err != nil {
        return nil, fmt.Errorf("config validation error: %v", err)
    }
    return &cfg, nil
}

func validateConfig(config *Config) error {
    if len(config.ThinkingServices) == 0 {
        return fmt.Errorf("no thinking services configured")
    }
    if len(config.Channels) == 0 {
        return fmt.Errorf("no channels configured")
    }
    for i, svc := range config.ThinkingServices {
        if svc.BaseURL == "" {
            return fmt.Errorf("thinking service %s has empty baseURL", svc.Name)
        }
        if svc.APIKey == "" {
            return fmt.Errorf("thinking service %s has empty apiKey", svc.Name)
        }
        if svc.Timeout <= 0 {
            return fmt.Errorf("thinking service %s has invalid timeout", svc.Name)
        }
        if svc.Model == "" {
            return fmt.Errorf("thinking service %s has empty model", svc.Name)
        }
        if svc.Mode == "" {
            config.ThinkingServices[i].Mode = "standard"
        } else if svc.Mode != "standard" && svc.Mode != "full" {
            return fmt.Errorf("thinking service %s unknown mode=%s", svc.Name, svc.Mode)
        }
    }
    return nil
}

func main() {
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

    cfg, err := loadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }
    log.Printf("Using config file: %s", viper.ConfigFileUsed())

    server := NewServer(cfg)

    done := make(chan os.Signal, 1)
    signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        if err := server.Start(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("start server error: %v", err)
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