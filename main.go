package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "strings"
    "sync"
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
    APIKey    string  `mapstructure:"api_key"`
    Timeout   int     `mapstructure:"timeout"`
    Retry     int     `mapstructure:"retry"`
    Weight    int     `mapstructure:"weight"`
}

type Channel struct {
    Name      string   `mapstructure:"name"`
    BaseURL   string   `mapstructure:"base_url"`
    KeyPrefix string   `mapstructure:"key_prefix"`
    Timeout   int      `mapstructure:"timeout"`
    Models    []string `mapstructure:"models"`
}

type GlobalConfig struct {
    MaxRetries     int    `mapstructure:"max_retries"`
    DefaultTimeout int    `mapstructure:"default_timeout"`
    ErrorCodes     struct {
        RetryOn []int `mapstructure:"retry_on"`
    } `mapstructure:"error_codes"`
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

    // 创建请求
    jsonData, err := json.Marshal(thinkingReq)
    if err != nil {
        return "", err
    }

    request, err := http.NewRequestWithContext(ctx, "POST",
        h.thinkingService.BaseURL+"/v1/chat/completions",
        bytes.NewBuffer(jsonData))
    if err != nil {
        return "", err
    }

    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+h.thinkingService.APIKey)

    // 执行请求
    client := &http.Client{}
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

    // 创建请求
    request, err := http.NewRequestWithContext(ctx, "POST",
        h.targetChannel.BaseURL+"/v1/chat/completions",
        bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }

    // 设置请求头
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+req.APIKey)

    // 执行请求
    client := &http.Client{}
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

func main() {
    // TODO: Add main server implementation
    log.Println("Starting DeepAI server...")
}