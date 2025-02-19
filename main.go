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
}

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
    Enabled          bool `mapstructure:"enabled"`
    AddToAllRequests bool `mapstructure:"add_to_all_requests"`
    Timeout          int  `mapstructure:"timeout"`
    ChainPreProcess  bool `mapstructure:"chain_preprocess"` // 是否对思考链做预处理
}

// LogConfig 日志配置
type LogConfig struct {
    Level    string      `mapstructure:"level"`
    Format   string      `mapstructure:"format"`
    Output   string      `mapstructure:"output"`
    FilePath string      `mapstructure:"file_path"`
    Debug    DebugConfig `mapstructure:"debug"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
    Enabled       bool   `mapstructure:"enabled"`
    Default       string `mapstructure:"default"`
    AllowInsecure bool   `mapstructure:"allow_insecure"`
}

// DebugConfig 调试日志配置
type DebugConfig struct {
    Enabled          bool `mapstructure:"enabled"`
    PrintRequest     bool `mapstructure:"print_request"`
    PrintResponse    bool `mapstructure:"print_response"`
    MaxContentLength int  `mapstructure:"max_content_length"`
}

// ============ OpenAI 兼容API相关结构 ============

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

// ============ “思考服务”返回的封装结果 ============

// ThinkingResponse 用于保存思考服务（标准 or 非标准）的输出
type ThinkingResponse struct {
    Content                string // 当思考服务有回答时放在这里
    ReasoningContent       string // 原始 reasoning_content
    ActualReasoningContent string // 最终给后端模型用的思考链
    IsStandardMode         bool   // 是否标准思考模型(判断是否实际返回了 reasoning_content)
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
    if !l.config.Global.Log.Debug.Enabled {
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

// ============ 实用函数 ============

// 从header拿Bearer
func extractRealAPIKey(fullKey string) string {
    parts := strings.Split(fullKey, "-")
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

// 对思考链做预处理（可选）
func preprocessReasoningChain(chain string) string {
    lines := strings.Split(chain, "\n")
    var processed []string
    for _, ln := range lines {
        ln = strings.TrimSpace(ln)
        if ln == "" {
            continue
        }
        // 这里可以过滤掉某些特定标记
        // if strings.HasPrefix(ln, "Note:") { ... }
        processed = append(processed, ln)
    }
    return strings.Join(processed, "\n")
}

// ============ Server 主体 ============

type Server struct {
    config *Config
    srv    *http.Server
}

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

    // OpenAI 兼容接口
    mux.HandleFunc("/v1/chat/completions", s.handleOpenAIRequests)
    mux.HandleFunc("/v1/models", s.handleOpenAIRequests)

    // 健康检查
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

// handleOpenAIRequests 核心入口
func (s *Server) handleOpenAIRequests(w http.ResponseWriter, r *http.Request) {
    logger := NewRequestLogger(s.config)

    // 路由判断
    if r.URL.Path == "/v1/chat/completions" && r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if r.URL.Path == "/v1/models" && r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // 解析 channel
    fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    realKey := extractRealAPIKey(fullAPIKey)
    channelID := extractChannelID(fullAPIKey)

    logger.Log("Incoming request: %s (APIKey=%s) channelID=%s",
        r.URL.Path, logSafeKey(fullAPIKey), channelID)

    // 查找对应 channel
    ch, ok := s.config.Channels[channelID]
    if !ok {
        http.Error(w, "Invalid channel", http.StatusBadRequest)
        return
    }

    // 如果是 /v1/models => 转发 GET
    if r.URL.Path == "/v1/models" {
        req := &ChatCompletionRequest{APIKey: realKey}
        s.forwardModelsRequest(w, r.Context(), req, ch, logger)
        return
    }

    // /v1/chat/completions => 解析 body
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

    // 选择思考服务
    thinkingSvc := s.getWeightedRandomThinkingService()
    logger.Log("Chosen thinking service: %s (key=%s)",
        thinkingSvc.Name, logSafeKey(thinkingSvc.APIKey))

    // 是否流式
    if userReq.Stream {
        // 流式处理
        handler, err := NewStreamHandler(w, thinkingSvc, ch, s.config, logger)
        if err != nil {
            http.Error(w, "Streaming not supported", http.StatusInternalServerError)
            return
        }
        if err := handler.Handle(r.Context(), &userReq); err != nil {
            logger.Log("Stream handler error: %v", err)
            // 这里也可以再返回一些错误 SSE
            return
        }
    } else {
        // 非流式：先调用思考服务 -> 得到思考链 -> 拼装后转发给最终模型
        tResp, err := s.callThinkingService(ctxWithTimeout(r.Context(), s.config.Global.Thinking.Timeout), &userReq, thinkingSvc, logger)
        if err != nil {
            logger.Log("Thinking service error: %v", err)
            http.Error(w, "Thinking service error", http.StatusInternalServerError)
            return
        }
        finalReq := s.prepareFinalRequest(&userReq, tResp, logger)
        s.forwardRequestNonStream(w, finalReq, ch, logger)
    }
}

// ========== /v1/models 转发(只 GET) ==========

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
        // 所有权重<=0时，默认返回第一个
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
    // 理论不会走到这里
    return tlist[0]
}

// ========== 1) 非流式 => 思考服务 ==========

func (s *Server) callThinkingService(ctx context.Context, userReq *ChatCompletionRequest,
    svc ThinkingService, logger *RequestLogger) (*ThinkingResponse, error) {

    // 构造思考服务请求
    thinkReq := *userReq
    thinkReq.Model = svc.Model
    thinkReq.APIKey = svc.APIKey
    // 特别注意：如果需要额外加 prompt，也可以在这里加 “system消息”

    reqBody, _ := json.Marshal(thinkReq)
    if s.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("Thinking Service Request (Non-Stream)", string(reqBody), s.config.Global.Log.Debug.MaxContentLength)
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
    if s.config.Global.Log.Debug.PrintResponse {
        logger.LogContent("Thinking Service Response (Non-Stream)", string(respBytes), s.config.Global.Log.Debug.MaxContentLength)
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

    // 组装结果
    tResp := &ThinkingResponse{
        Content: ccr.Choices[0].Message.Content,
    }
    // 判断是否有 reasoning_content
    if ccr.Choices[0].Message.ReasoningContent != nil {
        raw := ""
        switch v := ccr.Choices[0].Message.ReasoningContent.(type) {
        case string:
            raw = strings.TrimSpace(v)
        case map[string]interface{}:
            // 可能是 json object
            b, _ := json.Marshal(v)
            raw = strings.TrimSpace(string(b))
        }
        if raw != "" {
            tResp.IsStandardMode = true
            if s.config.Global.Thinking.ChainPreProcess {
                tResp.ActualReasoningContent = preprocessReasoningChain(raw)
            } else {
                tResp.ActualReasoningContent = raw
            }
            tResp.ReasoningContent = raw
        }
    }

    // 非标准模型 => 把 content 当做思考链
    if !tResp.IsStandardMode {
        tResp.ActualReasoningContent = tResp.Content
        tResp.ReasoningContent = ""
    }

    return tResp, nil
}

// ========== 2) 拼装对最终模型的请求 ==========

func (s *Server) prepareFinalRequest(userReq *ChatCompletionRequest, tResp *ThinkingResponse, logger *RequestLogger) *ChatCompletionRequest {
    finalReq := *userReq

    // 根据是否为标准模型, 拼装 system 提示
    var systemPrompt string
    if tResp.IsStandardMode {
        // 标准思考模型
        systemPrompt = fmt.Sprintf("Previous reasoning process:\n%s\nPlease refine answer accordingly.",
            tResp.ActualReasoningContent)
    } else {
        // 非标准
        systemPrompt = fmt.Sprintf("Based on the following reasoning process:\n%s\nProvide the best final answer.",
            tResp.ActualReasoningContent)
    }

    finalReq.Messages = append([]ChatCompletionMessage{
        {Role: "system", Content: systemPrompt},
    }, finalReq.Messages...)

    if s.config.Global.Log.Debug.PrintRequest {
        logger.LogContent("Enhanced Final Request", finalReq, s.config.Global.Log.Debug.MaxContentLength)
    }

    return &finalReq
}

// ========== 3) 非流式 => 最终模型 ==========

func (s *Server) forwardRequestNonStream(w http.ResponseWriter, finalReq *ChatCompletionRequest,
    ch Channel, logger *RequestLogger) {

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

    // 原样拷贝给用户
    for k, vs := range resp.Header {
        for _, v := range vs {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    w.Write(respBytes)
}

// ========== 4) 流式处理器 ==========

// StreamHandler 专门处理 “流式+思考服务 => (可能二次) => 流式最终模型” 的逻辑
type StreamHandler struct {
    w               http.ResponseWriter
    flusher         http.Flusher
    thinkingSvc     ThinkingService
    channel         Channel
    config          *Config
    logger          *RequestLogger

    // 下方用于收集思考链
    isStdModel      bool
    chainBuf        strings.Builder
    thinkingDone    bool // 是否完整结束了思考服务流
}

// NewStreamHandler 创建
func NewStreamHandler(w http.ResponseWriter, tSvc ThinkingService, ch Channel,
    cfg *Config, logger *RequestLogger) (*StreamHandler, error) {

    flusher, ok := w.(http.Flusher)
    if !ok {
        return nil, fmt.Errorf("streaming not supported")
    }
    return &StreamHandler{
        w:           w,
        flusher:     flusher,
        thinkingSvc: tSvc,
        channel:     ch,
        config:      cfg,
        logger:      logger,
    }, nil
}

// Handle 核心: 先流式读思考 => 拼装 => 再流式读最终通道 => 转发给用户
func (h *StreamHandler) Handle(ctx context.Context, userReq *ChatCompletionRequest) error {
    // 设置 SSE 头
    h.w.Header().Set("Content-Type", "text/event-stream")
    h.w.Header().Set("Cache-Control", "no-cache")
    h.w.Header().Set("Connection", "keep-alive")

    // 1) 获取思考链(流式)
    err := h.streamThinking(ctx, userReq)
    if err != nil {
        return err
    }

    // 2) 拼装 finalReq
    finalReq := h.prepareFinalRequest(userReq)

    // 3) 请求最终模型(流式) => 返回给用户
    return h.streamFinalResponse(ctx, finalReq)
}

// streamThinking 向思考服务发起流式请求，并根据 是否标准模型 决定是否把思考内容转发给用户
func (h *StreamHandler) streamThinking(ctx context.Context, userReq *ChatCompletionRequest) error {
    reqCopy := *userReq
    reqCopy.Stream = true
    reqCopy.Model = h.thinkingSvc.Model
    reqCopy.APIKey = h.thinkingSvc.APIKey

    // 构造 body
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
    var done bool

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        line, err := reader.ReadString('\n')
        if err != nil {
            if err == io.EOF {
                // 如果出现 EOF，认为思考结束
                done = true
            } else {
                return err
            }
        }
        line = strings.TrimSpace(line)
        if line == "" {
            if done {
                // 流结束
                h.thinkingDone = true
                break
            }
            continue
        }

        if !strings.HasPrefix(line, "data: ") {
            if done {
                h.thinkingDone = true
                break
            }
            continue
        }
        data := strings.TrimPrefix(line, "data: ")

        if data == "[DONE]" {
            h.thinkingDone = true
            break
        }

        // 解析 SSE 数据
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
            h.logger.Log("Parse chunk error: %v => %s", e, data)
            continue
        }
        if len(chunk.Choices) == 0 {
            continue
        }

        c := chunk.Choices[0]
        // 如果出现 reasoning_content，标记为标准模型
        if c.Delta.ReasoningContent != "" {
            h.isStdModel = true
        }

        // —— 处理要不要转发给用户：——
        //   若 isStdModel => 标准思考模型 => 在流式阶段就把 reasoning_content (或 content) 原样 SSE 发给前端
        //   若 非标准模型 => 不给用户看，只在后台收集
        if h.isStdModel {
            // 把 reasoning_content / content 都转给用户
            sseObj := map[string]interface{}{
                "choices": []map[string]interface{}{
                    {
                        "delta": map[string]string{
                            "content":           c.Delta.Content,
                            "reasoning_content": c.Delta.ReasoningContent,
                        },
                    },
                },
            }
            b, _ := json.Marshal(sseObj)
            sseLine := "data: " + string(b) + "\n\n"
            _, _ = h.w.Write([]byte(sseLine))
            h.flusher.Flush()
        }

        // 收集思考链
        //   - 如果是标准模型 => 优先收集 reasoning_content 中的文本
        //   - 如果是非标准模型 => 收集 content
        if c.Delta.ReasoningContent != "" {
            part := strings.TrimSpace(c.Delta.ReasoningContent)
            if h.config.Global.Thinking.ChainPreProcess {
                part = preprocessReasoningChain(part)
            }
            h.chainBuf.WriteString(part)
        }
        if c.Delta.Content != "" && !h.isStdModel {
            // 非标准 => 把 content 也当作思考链
            h.chainBuf.WriteString(c.Delta.Content)
        }

        if c.FinishReason != nil {
            // 如果思考服务主动给出 finish_reason，则停止
            h.thinkingDone = true
            break
        }

        if done {
            h.thinkingDone = true
            break
        }
    }

    // 思考服务完成
    return nil
}

// prepareFinalRequest 利用收集到的 chainBuf 构造对最终模型的提示
func (h *StreamHandler) prepareFinalRequest(userReq *ChatCompletionRequest) *ChatCompletionRequest {
    finalReq := *userReq
    // 标准 vs 非标准 => 不同提示词
    if h.isStdModel {
        // 标准 => chainBuf 里是 reasoning_content
        prompt := fmt.Sprintf("Previous reasoning:\n%s\nPlease refine answer accordingly.", h.chainBuf.String())
        finalReq.Messages = append([]ChatCompletionMessage{
            {Role: "system", Content: prompt},
        }, finalReq.Messages...)
    } else {
        // 非标准 => chainBuf 全部当做思考链
        prompt := fmt.Sprintf("Non-standard reasoning process:\n%s\nPlease provide best final answer.", h.chainBuf.String())
        finalReq.Messages = append([]ChatCompletionMessage{
            {Role: "system", Content: prompt},
        }, finalReq.Messages...)
    }

    if h.config.Global.Log.Debug.PrintRequest {
        h.logger.LogContent("Final Channel Stream Request", finalReq, h.config.Global.Log.Debug.MaxContentLength)
    }

    return &finalReq
}

// streamFinalResponse => 向最终模型发起流式请求，把 SSE 原样转发给用户
func (h *StreamHandler) streamFinalResponse(ctx context.Context, finalReq *ChatCompletionRequest) error {
    reqBody, _ := json.Marshal(finalReq)
    if h.config.Global.Log.Debug.PrintRequest {
        h.logger.LogContent("Final Channel Stream Request JSON", string(reqBody), h.config.Global.Log.Debug.MaxContentLength)
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

        if strings.HasPrefix(line, "data: ") {
            // 原样转发
            _, _ = h.w.Write([]byte(line + "\n\n"))
            h.flusher.Flush()
        }
        if line == "data: [DONE]" {
            // 最终结束
            break
        }
    }
    return nil
}

// ========== HTTP Client & Config 加载 ==========

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
        // 若无指定, 依次尝试这些默认位置
        ex, _ := os.Executable()
        exeDir := filepath.Dir(ex)
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

        // 顺序读取，直到读取成功
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

    return &c, nil
}

func validateConfig(c *Config) error {
    if len(c.ThinkingServices) == 0 {
        return fmt.Errorf("no thinking_services configured")
    }
    if len(c.Channels) == 0 {
        return fmt.Errorf("no channels configured")
    }
    return nil
}

// ========== main入口 ==========

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