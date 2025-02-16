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
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "path/filepath"
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
    ThinkingServices []ThinkingService     `mapstructure:"thinking_services"`
    Channels        map[string]Channel    `mapstructure:"channels"`
    Global          GlobalConfig          `mapstructure:"global"`
}

type ThinkingService struct {
    ID        int     `mapstructure:"id"`
    Name      string  `mapstructure:"name"`
    Model     string  `mapstructure:"model"`
    BaseURL   string  `mapstructure:"base_url"`
    APIPath   string  `mapstructure:"api_path"`
    APIKey    string  `mapstructure:"api_key"`
    Timeout   int     `mapstructure:"timeout"`
    Retry     int     `mapstructure:"retry"`
    Weight    int     `mapstructure:"weight"`
    Proxy     string  `mapstructure:"proxy"`
}

func (s *ThinkingService) GetFullURL() string {
    return s.BaseURL + s.APIPath
}

type Channel struct {
    Name      string   `mapstructure:"name"`
    BaseURL   string   `mapstructure:"base_url"`
    APIPath   string   `mapstructure:"api_path"`
    Timeout   int      `mapstructure:"timeout"`
    Proxy     string   `mapstructure:"proxy"`
}

func (c *Channel) GetFullURL() string {
    return c.BaseURL + c.APIPath
}

type ProxyConfig struct {
    Enabled       bool   `mapstructure:"enabled"`
    Default       string `mapstructure:"default"`
    AllowInsecure bool   `mapstructure:"allow_insecure"`
}

type GlobalConfig struct {
    MaxRetries     int    `mapstructure:"max_retries"`
    DefaultTimeout int    `mapstructure:"default_timeout"`
    ErrorCodes     struct {
        RetryOn []int `mapstructure:"retry_on"`
    } `mapstructure:"error_codes"`
    Log struct {
        Level    string `mapstructure:"level"`
        Format   string `mapstructure:"format"`
        Output   string `mapstructure:"output"`
        FilePath string `mapstructure:"file_path"`
    } `mapstructure:"log"`
    Server struct {
        Port         int    `mapstructure:"port"`
        Host         string `mapstructure:"host"`
        ReadTimeout  int    `mapstructure:"read_timeout"`
        WriteTimeout int    `mapstructure:"write_timeout"`
        IdleTimeout  int    `mapstructure:"idle_timeout"`
    } `mapstructure:"server"`
    Proxy         ProxyConfig  `mapstructure:"proxy"`
    ConfigPaths   []string     `mapstructure:"config_paths"`
    Thinking      ThinkingConfig `mapstructure:"thinking"`
}

type ThinkingConfig struct {
    Enabled           bool `mapstructure:"enabled"`
    AddToAllRequests  bool `mapstructure:"add_to_all_requests"`
    Timeout          int  `mapstructure:"timeout"`
}

// API相关结构
type ChatCompletionRequest struct {
    Model       string                  `json:"model"`
    Messages    []ChatCompletionMessage `json:"messages"`
    Temperature float64                 `json:"temperature,omitempty"`
    MaxTokens   int                    `json:"max_tokens,omitempty"`
    Stream      bool                    `json:"stream,omitempty"`
    APIKey      string                 `json:"-"` // 用于内部传递，不序列化
}

type ChatCompletionMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
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
    FinishReason string               `json:"finish_reason"`
}

type Usage struct {
    PromptTokens     int `json:"prompt_tokens"`
    CompletionTokens int `json:"completion_tokens"`
    TotalTokens      int `json:"total_tokens"`
}

// 日志记录结构
type RequestLogger struct {
    RequestID string
    Model     string
    StartTime time.Time
    logs      []string
}

func NewRequestLogger(model string) *RequestLogger {
    return &RequestLogger{
        RequestID: uuid.New().String(),
        Model:     model,
        StartTime: time.Now(),
        logs:      make([]string, 0),
    }
}

func (l *RequestLogger) Log(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    l.logs = append(l.logs, fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), msg))
    log.Printf("[RequestID: %s] %s", l.RequestID, msg)
}

// API Key 解析函数
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

// 安全的API Key日志记录
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

// NewServer 创建服务器实例
func NewServer(config *Config) *Server {
    return &Server{
        config: config,
    }
}

// Start 启动服务器
func (s *Server) Start() error {
    mux := http.NewServeMux()
    mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
    mux.HandleFunc("/health", s.handleHealth)

    s.srv = &http.Server{
        Addr:    fmt.Sprintf("%s:%d", s.config.Global.Server.Host, s.config.Global.Server.Port),
        Handler: mux,
        ReadTimeout:  time.Duration(s.config.Global.Server.ReadTimeout) * time.Second,
        WriteTimeout: time.Duration(s.config.Global.Server.WriteTimeout) * time.Second,
        IdleTimeout:  time.Duration(s.config.Global.Server.IdleTimeout) * time.Second,
    }

    log.Printf("Server starting on %s\n", s.srv.Addr)
    return s.srv.ListenAndServe()
}

// Shutdown 优雅关闭服务器
func (s *Server) Shutdown(ctx context.Context) error {
    return s.srv.Shutdown(ctx)
}

// handleHealth 健康检查处理器
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// handleChatCompletions 处理聊天补全请求
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var req ChatCompletionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // 获取并解析 API Key
    fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    apiKey := extractRealAPIKey(fullAPIKey)
    channelID := extractChannelID(fullAPIKey)

    logger := NewRequestLogger(req.Model)
    logger.Log("Received request with API Key: %s", logAPIKey(fullAPIKey))
    logger.Log("Extracted channel ID: %s", channelID)
    logger.Log("Extracted real API Key: %s", logAPIKey(apiKey))

    // 获取目标通道
    targetChannel, ok := s.config.Channels[channelID]
    if !ok {
        http.Error(w, "Invalid channel", http.StatusBadRequest)
        return
    }

    // 获取思考服务
    thinkingService := s.getHighestWeightThinkingService()
    logger.Log("Using thinking service: %s with API Key: %s", 
        thinkingService.Name, logAPIKey(thinkingService.APIKey))

    if req.Stream {
        handler, err := NewStreamHandler(w, thinkingService, targetChannel)
        if err != nil {
            http.Error(w, "Streaming not supported", http.StatusInternalServerError)
            return
        }
        
        req.APIKey = apiKey
        if err := handler.HandleRequest(r.Context(), &req); err != nil {
            logger.Log("Stream handler error: %v", err)
            return
        }
    } else {
        // 处理非流式请求
        thinkingResp, err := s.processThinkingContent(r.Context(), &req, thinkingService)
        if err != nil {
            logger.Log("Error processing thinking content: %v", err)
            http.Error(w, "Thinking service error", http.StatusInternalServerError)
            return
        }
        
        req.APIKey = apiKey
        enhancedReq := s.prepareEnhancedRequest(&req, thinkingResp)
        
        logger.Log("Forwarding enhanced request to channel with API Key: %s", logAPIKey(apiKey))
        s.forwardRequest(w, r.Context(), enhancedReq, targetChannel)
    }
}

// getHighestWeightThinkingService 获取权重最高的思考服务
func (s *Server) getHighestWeightThinkingService() ThinkingService {
    var highest ThinkingService
    maxWeight := -1

    for _, service := range s.config.ThinkingServices {
        if service.Weight > maxWeight {
            maxWeight = service.Weight
            highest = service
        }
    }

    return highest
}

// ThinkingResponse 结构体
type ThinkingResponse struct {
    Content          string
    ReasoningContent string
    Confidence       float64
}

// 处理思考链内容
func (s *Server) processThinkingContent(ctx context.Context, req *ChatCompletionRequest, 
    thinkingService ThinkingService) (*ThinkingResponse, error) {
    
    log.Printf("Getting thinking content from service: %s", thinkingService.Name)
    log.Printf("Using thinking service API Key: %s", logAPIKey(thinkingService.APIKey))

    // 准备思考服务请求
    thinkingReq := *req
    thinkingReq.Model = thinkingService.Model
    thinkingReq.APIKey = thinkingService.APIKey
    
    // 为思考链处理添加特殊提示
    thinkingPrompt := ChatCompletionMessage{
        Role:    "system",
        Content: "Please provide a detailed reasoning process for your response. Think step by step.",
    }
    thinkingReq.Messages = append([]ChatCompletionMessage{thinkingPrompt}, thinkingReq.Messages...)
    
    jsonData, err := json.Marshal(thinkingReq)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal thinking request: %v", err)
    }

    client, err := createHTTPClient(thinkingService.Proxy, time.Duration(thinkingService.Timeout)*time.Second)
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

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("thinking service returned status %d: %s", resp.StatusCode, string(body))
    }

    var thinkingResp ChatCompletionResponse
    if err := json.NewDecoder(resp.Body).Decode(&thinkingResp); err != nil {
        return nil, fmt.Errorf("failed to decode thinking response: %v", err)
    }

    if len(thinkingResp.Choices) == 0 {
        return nil, fmt.Errorf("thinking service returned no choices")
    }

    result := &ThinkingResponse{
        Content: thinkingResp.Choices[0].Message.Content,
    }

    // 提取 reasoning_content
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

    // 如果没有获取到 reasoning_content，使用 content 作为备选
    if result.ReasoningContent == "" {
        result.ReasoningContent = result.Content
        result.Content = "Based on the above reasoning."
    }

    // 记录处理结果
    log.Printf("Processed thinking content:")
    log.Printf("- Content length: %d", len(result.Content))
    log.Printf("- Reasoning content length: %d", len(result.ReasoningContent))

    return result, nil
}

// prepareEnhancedRequest 准备增强的请求
func (s *Server) prepareEnhancedRequest(originalReq *ChatCompletionRequest, 
    thinkingResp *ThinkingResponse) *ChatCompletionRequest {
    
    enhancedReq := *originalReq

    // 构建系统提示
    systemPrompt := fmt.Sprintf(`Based on the following reasoning process:
Reasoning: %s

And the conclusion:
%s

Please provide a response that incorporates this analysis while maintaining natural conversation flow.`,
        thinkingResp.ReasoningContent,
        thinkingResp.Content)

    // 添加系统消息
    enhancedReq.Messages = append([]ChatCompletionMessage{{
        Role:    "system",
        Content: systemPrompt,
    }}, enhancedReq.Messages...)

    return &enhancedReq
}

// forwardRequest 转发请求到目标通道
func (s *Server) forwardRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest, 
    targetChannel Channel) {
    
    log.Printf("Forwarding request details:")
    log.Printf("- Channel: %s", targetChannel.Name)
    log.Printf("- URL: %s", targetChannel.GetFullURL())
    log.Printf("- Model: %s", req.Model)
    log.Printf("- Input API Key: %s", logAPIKey(req.APIKey))
    
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

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Error response from target: Status: %d, Body: %s", resp.StatusCode, string(body))
        http.Error(w, fmt.Sprintf("Target server error: %s", resp.Status), resp.StatusCode)
        return
    }

    for key, values := range resp.Header {
        for _, value := range values {
            w.Header().Add(key, value)
        }
    }

    w.WriteHeader(resp.StatusCode)

    if _, err := io.Copy(w, resp.Body); err != nil {
        log.Printf("Error copying response: %v", err)
    }
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
}

func NewStreamHandler(w http.ResponseWriter, thinkingService ThinkingService, targetChannel Channel) (*StreamHandler, error) {
    flusher, ok := w.(http.Flusher)
    if !ok {
        return nil, fmt.Errorf("streaming not supported")
    }

    return &StreamHandler{
        thinkingService: thinkingService,
        targetChannel:   targetChannel,
        writer:         w,
        flusher:        flusher,
    }, nil
}

func (h *StreamHandler) HandleRequest(ctx context.Context, req *ChatCompletionRequest) error {
    h.writer.Header().Set("Content-Type", "text/event-stream")
    h.writer.Header().Set("Cache-Control", "no-cache")
    h.writer.Header().Set("Connection", "keep-alive")

    collector := &ThinkingStreamCollector{}

    thinkingContent, err := h.streamThinking(ctx, req, collector)
    if err != nil {
        return fmt.Errorf("thinking stream error: %v", err)
    }

    if !collector.IsCompleted() {
        return fmt.Errorf("thinking stream incomplete")
    }

    finalReq := h.prepareFinalRequest(req, thinkingContent)
    return h.streamFinalResponse(ctx, finalReq)
}

func (h *StreamHandler) streamThinking(ctx context.Context, req *ChatCompletionRequest, collector *ThinkingStreamCollector) (string, error) {
    thinkingReq := *req
    thinkingReq.Stream = true
    thinkingReq.Model = h.thinkingService.Model
    thinkingReq.APIKey = h.thinkingService.APIKey

    jsonData, err := json.Marshal(thinkingReq)
    if err != nil {
        return "", err
    }

    client, err := createHTTPClient(h.thinkingService.Proxy, time.Duration(h.thinkingService.Timeout)*time.Second)
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
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            return "", err
        }

        if len(line) <= 1 {
            continue
        }

        if bytes.HasPrefix(line, []byte("data: ")) {
            data := bytes.TrimPrefix(line, []byte("data: "))
            
            if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
                collector.SetCompleted()
                break
            }

            var streamResp struct {
                Choices []struct {
                    Delta struct {
                        Content string `json:"content"`
                        Role    string `json:"role"`
                    } `json:"delta"`
                } `json:"choices"`
            }

            if err := json.Unmarshal(data, &streamResp); err != nil {
                log.Printf("Error parsing stream response: %v", err)
                continue
            }

            h.writer.Write(line)
            h.flusher.Flush()

            if len(streamResp.Choices) > 0 {
                collector.Write([]byte(streamResp.Choices[0].Delta.Content))
            }
        }
    }

    return collector.GetContent(), nil
}

func (h *StreamHandler) prepareFinalRequest(originalReq *ChatCompletionRequest, thinkingContent string) *ChatCompletionRequest {
    finalReq := *originalReq

    thinkingMsg := ChatCompletionMessage{
        Role:    "system",
        Content: fmt.Sprintf("Previous thinking process:\n%s\nPlease consider the above thinking process in your response.", thinkingContent),
    }

    finalReq.Messages = append([]ChatCompletionMessage{thinkingMsg}, finalReq.Messages...)
    return &finalReq
}

func (h *StreamHandler) streamFinalResponse(ctx context.Context, req *ChatCompletionRequest) error {
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
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            return err
        }

        h.writer.Write(line)
        h.flusher.Flush()
    }

    return nil
}

// createHTTPClient 创建支持代理的HTTP客户端
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

// maskSensitiveHeaders 遮蔽敏感的header信息
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

// loadConfig 加载配置文件
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

// validateConfig 验证配置是否有效
func validateConfig(config *Config) error {
    if len(config.ThinkingServices) == 0 {
        return fmt.Errorf("no thinking services configured")
    }

    if len(config.Channels) == 0 {
        return fmt.Errorf("no channels configured")
    }

    for _, service := range config.ThinkingServices {
        if service.BaseURL == "" {
            return fmt.Errorf("thinking service %s has invalid timeout", service.Name)
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
    // 设置日志格式 - 包含日期、时间（精确到微秒）、文件名和行号
    log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

    // 加载配置文件
    config, err := loadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 输出使用的配置文件路径
    log.Printf("Using config file: %s", viper.ConfigFileUsed())

    // 创建服务器实例
    server := NewServer(config)

    // 处理优雅关闭 - 设置中断信号通道
    done := make(chan os.Signal, 1)
    signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

    // 在后台启动服务器
    go func() {
        if err := server.Start(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Failed to start server: %v", err)
        }
    }()

    log.Printf("Server started successfully")

    // 等待中断信号
    <-done
    log.Print("Server stopping...")

    // 创建关闭超时上下文
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // 优雅关闭服务器
    if err := server.Shutdown(ctx); err != nil {
        log.Printf("Server forced to shutdown: %v", err)
    }

    log.Print("Server stopped")
}