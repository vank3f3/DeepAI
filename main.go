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

// 流式响应结构
type ChatStreamResponse struct {
    ID      string `json:"id"`
    Object  string `json:"object"`
    Created int64  `json:"created"`
    Model   string `json:"model"`
    Choices []struct {
        Delta struct {
            Content string `json:"content"`
            Role    string `json:"role"`
        } `json:"delta"`
        Index        int    `json:"index"`
        FinishReason string `json:"finish_reason"`
    } `json:"choices"`
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
    // 创建路由
    mux := http.NewServeMux()
    
    // 注册路由处理器
    mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
    mux.HandleFunc("/health", s.handleHealth)

    // 创建 HTTP 服务器
    s.srv = &http.Server{
        Addr:    fmt.Sprintf("%s:%d", s.config.Global.Server.Host, s.config.Global.Server.Port),
        Handler: mux,
        ReadTimeout:  time.Duration(s.config.Global.Server.ReadTimeout) * time.Second,
        WriteTimeout: time.Duration(s.config.Global.Server.WriteTimeout) * time.Second,
        IdleTimeout:  time.Duration(s.config.Global.Server.IdleTimeout) * time.Second,
    }

    // 启动服务器
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
    // 只接受 POST 请求
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // 解析请求
    var req ChatCompletionRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // 获取 API Key
    apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    if apiKey == "" {
        http.Error(w, "Missing API key", http.StatusUnauthorized)
        return
    }
    req.APIKey = apiKey

    // 根据模型确定目标通道
    targetChannel, ok := s.config.Channels[getChannelIDFromModel(req.Model)]
    if !ok {
        http.Error(w, "Unsupported model", http.StatusBadRequest)
        return
    }

    // 检查是否是思考型请求
    if isThinkingModel(req.Model) {
        // 获取权重最高的思考服务
        thinkingService := s.getHighestWeightThinkingService()
        
        if req.Stream {
            // 处理流式请求
            handler, err := NewStreamHandler(w, thinkingService, targetChannel)
            if err != nil {
                http.Error(w, "Streaming not supported", http.StatusInternalServerError)
                return
            }
            
            if err := handler.HandleRequest(r.Context(), &req); err != nil {
                log.Printf("Stream handler error: %v", err)
                return
            }
        } else {
            // 处理非流式请求
            s.handleNonStreamRequest(w, r.Context(), &req, thinkingService, targetChannel)
        }
    } else {
        // 直接转发到目标通道
        s.forwardRequest(w, r.Context(), &req, targetChannel)
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

// handleNonStreamRequest 处理非流式请求
func (s *Server) handleNonStreamRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest, 
    thinkingService ThinkingService, targetChannel Channel) {
    
    // 获取思考链内容
    thinkingResp, err := s.getThinkingContent(ctx, req, thinkingService)
    if err != nil {
        http.Error(w, fmt.Sprintf("Thinking service error: %v", err), http.StatusInternalServerError)
        return
    }

    // 将思考链内容添加到请求中
    if len(thinkingResp.Choices) > 0 {
        thinkingContent := thinkingResp.Choices[0].Message.Content
        req.Messages = append([]ChatCompletionMessage{{
            Role:    "system",
            Content: fmt.Sprintf("Previous thinking process:\n%s\nPlease consider the above thinking process in your response.", 
                thinkingContent),
        }}, req.Messages...)
    }

    // 转发到目标通道
    s.forwardRequest(w, ctx, req, targetChannel)
}

// getThinkingContent 获取思考链内容
func (s *Server) getThinkingContent(ctx context.Context, req *ChatCompletionRequest, 
    thinkingService ThinkingService) (*ChatCompletionResponse, error) {
    
    // 准备请求
    jsonData, err := json.Marshal(req)
    if err != nil {
        return nil, err
    }

    // 创建HTTP客户端
    client, err := createHTTPClient(thinkingService.Proxy, time.Duration(thinkingService.Timeout)*time.Second)
    if err != nil {
        return nil, fmt.Errorf("failed to create HTTP client: %v", err)
    }

    // 创建请求
    request, err := http.NewRequestWithContext(ctx, "POST",
        thinkingService.GetFullURL(),
        strings.NewReader(string(jsonData)))
    if err != nil {
        return nil, err
    }

    // 设置请求头
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+thinkingService.APIKey)

    // 执行请求
    resp, err := client.Do(request)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // 解析响应
    var thinkingResp ChatCompletionResponse
    if err := json.NewDecoder(resp.Body).Decode(&thinkingResp); err != nil {
        return nil, err
    }

    return &thinkingResp, nil
}

// forwardRequest 转发请求到目标通道
func (s *Server) forwardRequest(w http.ResponseWriter, ctx context.Context, req *ChatCompletionRequest, 
    targetChannel Channel) {
    
    // 准备请求
    jsonData, err := json.Marshal(req)
    if err != nil {
        http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
        return
    }

    // 创建HTTP客户端
    client, err := createHTTPClient(targetChannel.Proxy, time.Duration(targetChannel.Timeout)*time.Second)
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to create HTTP client: %v", err), http.StatusInternalServerError)
        return
    }

    // 创建请求
    request, err := http.NewRequestWithContext(ctx, "POST",
        targetChannel.GetFullURL(),
        strings.NewReader(string(jsonData)))
    if err != nil {
        http.Error(w, "Failed to create request", http.StatusInternalServerError)
        return
    }

    // 设置请求头
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+req.APIKey)
    
    // 执行请求
    resp, err := client.Do(request)
    if err != nil {
        http.Error(w, "Failed to forward request", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    // 复制响应头
    for key, values := range resp.Header {
        for _, value := range values {
            w.Header().Add(key, value)
        }
    }

    // 设置状态码
    w.WriteHeader(resp.StatusCode)

    // 复制响应体
    if _, err := io.Copy(w, resp.Body); err != nil {
        log.Printf("Error copying response: %v", err)
    }
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
    // 设置SSE headers
    h.writer.Header().Set("Content-Type", "text/event-stream")
    h.writer.Header().Set("Cache-Control", "no-cache")
    h.writer.Header().Set("Connection", "keep-alive")

    // 创建思考链收集器
    collector := &ThinkingStreamCollector{}

    // 获取思考链(流式)
    thinkingContent, err := h.streamThinking(ctx, req, collector)
    if err != nil {
        return fmt.Errorf("thinking stream error: %v", err)
    }

    // 等待思考链完成
    if !collector.IsCompleted() {
        return fmt.Errorf("thinking stream incomplete")
    }

    // 准备第二阶段请求
    finalReq := h.prepareFinalRequest(req, thinkingContent)

    // 执行最终请求
    return h.streamFinalResponse(ctx, finalReq)
}

func (h *StreamHandler) streamThinking(ctx context.Context, req *ChatCompletionRequest, collector *ThinkingStreamCollector) (string, error) {
    // 准备思考链请求
    thinkingReq := *req // 复制请求
    thinkingReq.Stream = true

    // 准备请求
    jsonData, err := json.Marshal(thinkingReq)
    if err != nil {
        return "", err
    }

    // 创建HTTP客户端
    client, err := createHTTPClient(h.thinkingService.Proxy, time.Duration(h.thinkingService.Timeout)*time.Second)
    if err != nil {
        return "", fmt.Errorf("failed to create HTTP client: %v", err)
    }

    // 创建请求
    request, err := http.NewRequestWithContext(ctx, "POST",
        h.thinkingService.GetFullURL(),
        bytes.NewBuffer(jsonData))
    if err != nil {
        return "", err
    }

    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+h.thinkingService.APIKey)

    // 执行请求
    resp, err := client.Do(request)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    // 处理流式响应
    reader := bufio.NewReader(resp.Body)
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            return "", err
        }

        // 跳过空行
        if len(line) <= 1 {
            continue
        }

        // 处理SSE数据
        if bytes.HasPrefix(line, []byte("data: ")) {
            data := bytes.TrimPrefix(line, []byte("data: "))
            
            // 检查是否是结束标记
            if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
                collector.SetCompleted()
                break
            }

            // 解析流式响应
            var streamResp ChatStreamResponse
            if err := json.Unmarshal(data, &streamResp); err != nil {
                continue
            }

            // 转发给客户端
            h.writer.Write(line)
            h.flusher.Flush()

            // 收集内容
            if len(streamResp.Choices) > 0 {
                collector.Write([]byte(streamResp.Choices[0].Delta.Content))
            }
        }
    }

    return collector.GetContent(), nil
}

func (h *StreamHandler) prepareFinalRequest(originalReq *ChatCompletionRequest, thinkingContent string) *ChatCompletionRequest {
    // 创建新请求
    finalReq := *originalReq

    // 添加thinking content作为system消息
    thinkingMsg := ChatCompletionMessage{
        Role:    "system",
        Content: fmt.Sprintf("Previous thinking process:\n%s\nPlease consider the above thinking process in your response.", thinkingContent),
    }

    finalReq.Messages = append([]ChatCompletionMessage{thinkingMsg}, finalReq.Messages...)
    
    return &finalReq
}

func (h *StreamHandler) streamFinalResponse(ctx context.Context, req *ChatCompletionRequest) error {
    // 准备请求
    jsonData, err := json.Marshal(req)
    if err != nil {
        return err
    }

    // 创建HTTP客户端
    client, err := createHTTPClient(h.targetChannel.Proxy, time.Duration(h.targetChannel.Timeout)*time.Second)
    if err != nil {
        return fmt.Errorf("failed to create HTTP client: %v", err)
    }

    // 创建请求
    request, err := http.NewRequestWithContext(ctx, "POST",
        h.targetChannel.GetFullURL(),
        bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }

    // 设置请求头
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+req.APIKey)

    // 执行请求
    resp, err := client.Do(request)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    // 直接转发流式响应
    reader := bufio.NewReader(resp.Body)
    for {
        line, err := reader.ReadBytes('\n')
        if err != nil {
            if err == io.EOF {
                break
            }
            return err
        }

        // 转发数据
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
        // 解析代理URL
        parsedURL, err := url.Parse(proxyURL)
        if err != nil {
            return nil, fmt.Errorf("invalid proxy URL: %v", err)
        }

        switch parsedURL.Scheme {
        case "http", "https":
            transport.Proxy = http.ProxyURL(parsedURL)
        case "socks5":
            // 创建SOCKS5代理拨号器
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

// getChannelIDFromModel 从模型名称获取通道ID
func getChannelIDFromModel(model string) string {
    switch {
    case strings.HasPrefix(model, "gpt"):
        return "2" // OpenAI
    case strings.HasPrefix(model, "claude"):
        return "3" // Anthropic
    case strings.HasPrefix(model, "moonshot"):
        return "4" // Moonshot
    default:
        return "1" // DeepSeek
    }
}

// isThinkingModel 判断是否是思考型模型
func isThinkingModel(model string) bool {
    return strings.Contains(model, "o1") || strings.Contains(model, "o3") || 
           strings.Contains(model, "reasoner")
}

// loadConfig 加载配置文件
func loadConfig() (*Config, error) {
    // 解析命令行参数
    var configFile string
    flag.StringVar(&configFile, "config", "", "path to config file")
    flag.Parse()

    viper.SetConfigType("yaml")

    // 如果指定了配置文件
    if configFile != "" {
        viper.SetConfigFile(configFile)
    } else {
        // 获取可执行文件所在目录
        ex, err := os.Executable()
        if err != nil {
            return nil, err
        }
        exePath := filepath.Dir(ex)

        // 默认配置文件搜索路径
        defaultPaths := []string{
            filepath.Join(exePath, "config.yaml"),
            filepath.Join(exePath, "conf", "config.yaml"),
            "./config.yaml",
            "./conf/config.yaml",
        }

        // Windows系统添加额外路径
        if os.PathSeparator == '\\' {
            programData := os.Getenv("PROGRAMDATA")
            if programData != "" {
                defaultPaths = append(defaultPaths, filepath.Join(programData, "DeepAI", "config.yaml"))
            }
        } else {
            // Linux/Unix系统添加额外路径
            defaultPaths = append(defaultPaths, "/etc/deepai/config.yaml")
        }

        // 添加搜索路径
        for _, path := range defaultPaths {
            viper.AddConfigPath(filepath.Dir(path))
            if strings.Contains(path, ".yaml") {
                viper.SetConfigName(strings.TrimSuffix(filepath.Base(path), ".yaml"))
            }
        }
    }

    // 读取配置文件
    if err := viper.ReadInConfig(); err != nil {
        return nil, fmt.Errorf("failed to read config file: %v", err)
    }

    // 解析配置
    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal config: %v", err)
    }

    return &config, nil
}

func main() {
    // 加载配置
    config, err := loadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 输出使用的配置文件路径
    log.Printf("Using config file: %s", viper.ConfigFileUsed())

    // 创建服务器
    server := NewServer(config)

    // 处理优雅关闭
    done := make(chan os.Signal, 1)
    signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

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