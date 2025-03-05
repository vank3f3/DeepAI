package server

import (
	"bufio"
	"bytes"
	"context"
	"deepai/internal/api"
	"deepai/internal/config"
	"deepai/internal/logger"
	"deepai/internal/utils"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server 服务器结构
type Server struct {
	config *config.Config
	srv    *http.Server
}

var (
	randMu  sync.Mutex
	randGen = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// collectedReasoningBuffer 用于收集思考服务返回的reasoning_content
type collectedReasoningBuffer struct {
	builder strings.Builder
	mode    string
}

func (cb *collectedReasoningBuffer) append(text string) {
	cb.builder.WriteString(text)
}

func (cb *collectedReasoningBuffer) get() string {
	return cb.builder.String()
}

// StreamHandler 流式处理器
type StreamHandler struct {
	thinkingService config.ThinkingService
	targetChannel   config.Channel
	writer          http.ResponseWriter
	flusher         http.Flusher
	config          *config.Config
}

// ThinkingResponse 思考服务响应
type ThinkingResponse struct {
	Content          string
	ReasoningContent string
}

// NewServer 创建新的服务器
func NewServer(config *config.Config) *Server {
	return &Server{
		config: config,
	}
}

// Start 启动服务器
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("/v1/models", s.handleModels)
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

// Shutdown 关闭服务器
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// handleHealth 处理健康检查请求
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// handleModels 处理模型列表请求
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lgr := logger.NewRequestLogger(s.config)

	// 提取并验证 API Key
	fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	apiKey := logger.ExtractRealAPIKey(fullAPIKey)
	channelID := logger.ExtractChannelID(fullAPIKey)

	lgr.Log("Received models request with API Key: %s", logger.LogAPIKey(fullAPIKey))
	lgr.Log("Extracted channel ID: %s", channelID)
	lgr.Log("Extracted real API Key: %s", logger.LogAPIKey(apiKey))

	// 获取目标通道
	targetChannel, ok := s.config.Channels[channelID]
	if !ok {
		http.Error(w, "Invalid channel", http.StatusBadRequest)
		return
	}

	// 转发模型列表请求
	req := &api.ChatCompletionRequest{APIKey: apiKey}
	s.forwardModelsRequest(w, r.Context(), req, targetChannel)
}

// isTestRequest 检查是否为测试请求
func isTestRequest(req *api.ChatCompletionRequest) bool {
	if len(req.Messages) == 0 {
		return false
	}

	// 获取最后一条消息
	lastMsg := req.Messages[len(req.Messages)-1]

	// 检查是否为用户消息且内容为测试关键词
	if lastMsg.Role == "user" {
		content := strings.TrimSpace(strings.ToLower(lastMsg.Content))
		return content == "ping" || content == "hi"
	}

	return false
}

// generateTestResponse 生成测试请求的响应
func generateTestResponse(req *api.ChatCompletionRequest) interface{} {
	// 生成随机ID
	randomID := func(length int) string {
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, length)
		for i := range result {
			// 使用当前时间的纳秒部分作为随机源
			result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
			// 短暂延迟以确保不同字符
			time.Sleep(time.Nanosecond)
		}
		return string(result)
	}

	// 根据请求是否为流式返回不同格式的响应
	if req.Stream {
		// 返回SSE格式的响应
		return map[string]interface{}{
			"id":      fmt.Sprintf("chatcmpl-%s", randomID(29)),
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   req.Model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"delta": map[string]interface{}{
						"role":    "assistant",
						"content": "DeepAI service is running. This is a fast response for test requests.",
					},
					"finish_reason": "stop",
				},
			},
		}
	} else {
		// 返回标准格式的响应
		return map[string]interface{}{
			"id":      fmt.Sprintf("chatcmpl-%s", randomID(29)),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   req.Model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": "DeepAI service is running. This is a fast response for test requests.",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     0,
				"completion_tokens": 0,
				"total_tokens":      0,
			},
		}
	}
}

// handleTestRequest 处理测试请求并返回短路响应
func (s *Server) handleTestRequest(w http.ResponseWriter, req *api.ChatCompletionRequest) {
	w.Header().Set("Content-Type", "application/json")

	// 生成响应
	response := generateTestResponse(req)

	// 如果是流式请求，需要特殊处理
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		// 发送数据
		responseJSON, _ := json.Marshal(response)
		fmt.Fprintf(w, "data: %s\n\n", responseJSON)

		// 发送结束标记
		fmt.Fprintf(w, "data: [DONE]\n\n")

		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	} else {
		// 非流式请求直接返回JSON
		responseJSON, _ := json.Marshal(response)
		w.Write(responseJSON)
	}
}

// handleChatCompletions 处理聊天补全请求
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lgr := logger.NewRequestLogger(s.config)

	// 提取并验证 API Key
	fullAPIKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	apiKey := logger.ExtractRealAPIKey(fullAPIKey)
	channelID := logger.ExtractChannelID(fullAPIKey)

	lgr.Log("Received chat completion request with API Key: %s", logger.LogAPIKey(fullAPIKey))
	lgr.Log("Extracted channel ID: %s", channelID)
	lgr.Log("Extracted real API Key: %s", logger.LogAPIKey(apiKey))

	// 获取目标通道
	targetChannel, ok := s.config.Channels[channelID]
	if !ok {
		http.Error(w, "Invalid channel", http.StatusBadRequest)
		return
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		lgr.Log("Error reading request body: %v", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// 调试日志
	if s.config.Global.Log.Debug.PrintRequest {
		lgr.LogContent("Request", string(body), s.config.Global.Log.Debug.MaxContentLength)
	}

	// 解析请求
	var req api.ChatCompletionRequest
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.APIKey = apiKey

	// 处理模型名称
	if strings.HasPrefix(req.Model, s.config.Global.Model.Prefix) {
		req.Model = strings.TrimPrefix(req.Model, s.config.Global.Model.Prefix)
	}

	// 检查是否为测试请求，如果是则短路处理
	if isTestRequest(&req) {
		lgr.Log("Detected test request, providing fast response")
		s.handleTestRequest(w, &req)
		return
	}

	// 获取思考服务
	thinkingService := s.getWeightedRandomThinkingService()
	lgr.Log("Using thinking service: %s with API Key: %s", thinkingService.Name, logger.LogAPIKey(thinkingService.APIKey))

	// 处理流式或非流式请求
	if req.Stream {
		handler, err := NewStreamHandler(w, thinkingService, targetChannel, s.config)
		if err != nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		if err := handler.HandleRequest(r.Context(), &req); err != nil {
			lgr.Log("Stream handler error: %v", err)
		}
	} else {
		s.handleNonStreamRequest(w, r.Context(), &req, thinkingService, targetChannel, lgr)
	}
}

// handleNonStreamRequest 处理非流式请求
func (s *Server) handleNonStreamRequest(w http.ResponseWriter, ctx context.Context, req *api.ChatCompletionRequest,
	thinkingService config.ThinkingService, targetChannel config.Channel, lgr *logger.RequestLogger) {

	// 处理思考内容
	thinkingResp, err := s.processThinkingContent(ctx, req, thinkingService)
	if err != nil {
		lgr.Log("Error processing thinking content: %v", err)
		http.Error(w, "Thinking service error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 准备增强请求
	enhancedReq := s.prepareEnhancedRequest(req, thinkingResp, thinkingService)

	// 转发到目标通道
	s.forwardRequest(w, ctx, enhancedReq, targetChannel)
}

// NewStreamHandler 创建新的流式处理器
func NewStreamHandler(w http.ResponseWriter, thinkingService config.ThinkingService, targetChannel config.Channel, config *config.Config) (*StreamHandler, error) {
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

// HandleRequest 处理流式请求
func (h *StreamHandler) HandleRequest(ctx context.Context, req *api.ChatCompletionRequest) error {
	// 设置响应头
	h.writer.Header().Set("Content-Type", "text/event-stream")
	h.writer.Header().Set("Cache-Control", "no-cache")
	h.writer.Header().Set("Connection", "keep-alive")
	h.writer.WriteHeader(http.StatusOK)

	// 创建日志实例
	lgr := logger.NewRequestLogger(h.config)

	// 创建推理内容缓冲区
	reasonBuf := &collectedReasoningBuffer{
		mode: h.thinkingService.Mode,
	}

	// 调用思考服务并收集推理内容
	if err := h.streamThinkingService(ctx, req, reasonBuf, lgr); err != nil {
		lgr.Log("Error streaming thinking service: %v", err)
		return err
	}

	// 获取收集的推理内容
	reasoningCollected := reasonBuf.get()
	if reasoningCollected == "" {
		lgr.Log("Warning: Empty reasoning content collected")
	} else {
		lgr.Log("Successfully collected reasoning content (%d bytes)", len(reasoningCollected))
	}

	// 准备最终请求并发送到目标通道
	finalReq := h.prepareFinalRequest(req, reasoningCollected)
	if err := h.streamFinalChannel(ctx, finalReq, lgr); err != nil {
		lgr.Log("Error streaming final channel: %v", err)
		return err
	}

	return nil
}

// streamThinkingService 流式处理思考服务数据
func (h *StreamHandler) streamThinkingService(ctx context.Context, req *api.ChatCompletionRequest, reasonBuf *collectedReasoningBuffer, lgr *logger.RequestLogger) error {
	// 创建一个流式版的请求
	thinkReq := api.ChatCompletionRequest{
		Model:    h.thinkingService.Model,
		Messages: req.Messages,
		Stream:   true,
	}

	// 设置温度参数（默认0.7）
	if req.Temperature != 0 {
		thinkReq.Temperature = req.Temperature
	} else {
		thinkReq.Temperature = 0.7
	}

	// 设置top_p参数（默认1.0）
	if req.TopP != 0 {
		thinkReq.TopP = req.TopP
	} else {
		thinkReq.TopP = 1.0
	}

	// max_tokens 直接使用用户设置的值，0 表示不限制
	thinkReq.MaxTokens = req.MaxTokens

	// 序列化请求
	jsonData, err := json.Marshal(thinkReq)
	if err != nil {
		return fmt.Errorf("marshal thinking request error: %v", err)
	}

	// 创建HTTP客户端
	client, err := utils.CreateHTTPClient(h.thinkingService.Proxy, time.Duration(h.thinkingService.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("create HTTP client error: %v", err)
	}

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.thinkingService.GetFullURL(), bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("create thinking request error: %v", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+h.thinkingService.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	// 添加可选的自定义头部
	if h.thinkingService.ReasoningEffort != "" && utils.IsValidReasoningEffort(h.thinkingService.ReasoningEffort) {
		httpReq.Header.Set("X-reasoning-effort", h.thinkingService.ReasoningEffort)
	}
	if h.thinkingService.ReasoningFormat != "" && utils.IsValidReasoningFormat(h.thinkingService.ReasoningFormat) {
		httpReq.Header.Set("X-reasoning-format", h.thinkingService.ReasoningFormat)
	}

	// 发送请求
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("thinking service request error: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("thinking service returned status=%d, body=%s", resp.StatusCode, string(body))
	}

	// 处理SSE流
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read thinking service response error: %v", err)
		}

		// 跳过空行或注释
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}

		// 解析SSE数据行
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				// 结束标记
				break
			}

			// 解析JSON
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content          string      `json:"content"`
						ReasoningContent interface{} `json:"reasoning_content"`
					} `json:"delta"`
				} `json:"choices"`
			}

			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				lgr.Log("Warning: Failed to unmarshal chunk: %v, data: %s", err, data)
				continue
			}

			// 处理标准模式
			if h.thinkingService.Mode == "standard" && len(chunk.Choices) > 0 {
				// 提取推理内容
				if rc, ok := chunk.Choices[0].Delta.ReasoningContent.(string); ok && rc != "" {
					reasonBuf.append(rc)

					// 将思考过程传给客户端（仅标准模式）
					fmt.Fprintf(h.writer, "data: %s\n\n", data)
					h.flusher.Flush()
				}

				// 如果是标准模式且配置了强制停止
				if h.thinkingService.ForceStopDeepThinking && chunk.Choices[0].Delta.Content != "" {
					lgr.Log("Standard mode with force_stop_deep_thinking: stopping at first content token")
					break
				}
			} else if h.thinkingService.Mode == "full" {
				// 全量模式：不发送给客户端，仅收集推理内容
				if rc, ok := chunk.Choices[0].Delta.ReasoningContent.(string); ok && rc != "" {
					reasonBuf.append(rc)
				}
			}
		}
	}

	return nil
}

// streamFinalChannel 流式处理最终通道
func (h *StreamHandler) streamFinalChannel(ctx context.Context, req *api.ChatCompletionRequest, lgr *logger.RequestLogger) error {
	// 序列化请求
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal final request error: %v", err)
	}

	// 创建HTTP客户端
	client, err := utils.CreateHTTPClient(h.targetChannel.Proxy, time.Duration(h.targetChannel.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("create HTTP client error: %v", err)
	}

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.targetChannel.GetFullURL(), bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("create final request error: %v", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	// 发送请求
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("final service request error: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("final service returned status=%d, body=%s", resp.StatusCode, string(body))
	}

	// 将最终通道的SSE流直接传递给客户端
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read final service response error: %v", err)
		}

		// 直接写入客户端
		fmt.Fprint(h.writer, line)
		h.flusher.Flush()
	}

	return nil
}

// prepareFinalRequest 准备最终请求
func (h *StreamHandler) prepareFinalRequest(originalReq *api.ChatCompletionRequest, reasoningCollected string) *api.ChatCompletionRequest {
	req := *originalReq

	// 构造思考过程消息
	var thinkingContent string
	if h.thinkingService.Mode == "full" {
		thinkingContent = fmt.Sprintf(
			`Let me analyze this step by step:

%s

Based on this analysis, here's my response:`,
			reasoningCollected,
		)
	} else {
		thinkingContent = fmt.Sprintf(
			`My thinking process:

%s

Now, let me provide my response based on this analysis.`,
			reasoningCollected,
		)
	}

	// 直接将思考过程追加到消息列表
	req.Messages = append(req.Messages, api.ChatCompletionMessage{
		Role:    "assistant",
		Content: thinkingContent,
	})

	// 保持用户设置的参数或使用默认值
	if req.Temperature == 0 {
		req.Temperature = 0.7
	}
	if req.TopP == 0 {
		req.TopP = 1.0
	}
	// max_tokens 为 0 或不设置时表示不限制长度
	// if req.MaxTokens == 0 {
	//     req.MaxTokens = 2000
	// }

	return &req
}

// prepareFinalRequest_system 准备最终请求，修改了System 定义
func (h *StreamHandler) prepareFinalRequest_system(originalReq *api.ChatCompletionRequest, reasoningCollected string) *api.ChatCompletionRequest {
	req := *originalReq

	// 构建系统提示
	var systemPrompt string
	if h.thinkingService.Mode == "full" {
		// 全量模式
		systemPrompt = fmt.Sprintf(
			`Consider the following detailed analysis (not shown to user):
%s

Provide a clear, concise response that incorporates insights from this analysis.`,
			reasoningCollected,
		)
	} else {
		// 标准模式
		systemPrompt = fmt.Sprintf(
			`Previous thinking process:
%s
Please consider the above thinking process in your response.`,
			reasoningCollected,
		)
	}

	// 添加系统消息
	req.Messages = append([]api.ChatCompletionMessage{
		{Role: "system", Content: systemPrompt},
	}, req.Messages...)

	return &req
}

// getWeightedRandomThinkingService 获取加权随机思考服务
func (s *Server) getWeightedRandomThinkingService() config.ThinkingService {
	if len(s.config.ThinkingServices) == 1 {
		return s.config.ThinkingServices[0]
	}

	// 计算权重总和
	totalWeight := 0
	for _, svc := range s.config.ThinkingServices {
		totalWeight += svc.Weight
	}

	// 生成随机数
	randMu.Lock()
	rnd := randGen.Intn(totalWeight) + 1
	randMu.Unlock()

	// 加权选择
	cumulativeWeight := 0
	for _, svc := range s.config.ThinkingServices {
		cumulativeWeight += svc.Weight
		if rnd <= cumulativeWeight {
			return svc
		}
	}

	// 默认返回第一个服务（理论上不会执行到这里）
	return s.config.ThinkingServices[0]
}

// processThinkingContent 处理思考内容
func (s *Server) processThinkingContent(ctx context.Context, req *api.ChatCompletionRequest, svc config.ThinkingService) (*ThinkingResponse, error) {
	// 创建思考请求
	thinkReq := api.ChatCompletionRequest{
		Model:    svc.Model,
		Messages: req.Messages,
		Stream:   false,
	}

	// 设置温度参数（默认0.7）
	if req.Temperature != 0 {
		thinkReq.Temperature = req.Temperature
	} else {
		thinkReq.Temperature = 0.7
	}

	// 设置top_p参数（默认1.0）
	if req.TopP != 0 {
		thinkReq.TopP = req.TopP
	} else {
		thinkReq.TopP = 1.0
	}

	// 设置max_tokens参数（默认2000）
	if req.MaxTokens != 0 {
		thinkReq.MaxTokens = req.MaxTokens
	} else {
		thinkReq.MaxTokens = 2000
	}

	// 准备请求
	jsonData, err := json.Marshal(thinkReq)
	if err != nil {
		return nil, fmt.Errorf("marshal thinking request error: %v", err)
	}

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, svc.GetFullURL(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create thinking request error: %v", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+svc.APIKey)

	// 添加可选的自定义头部
	if svc.ReasoningEffort != "" && utils.IsValidReasoningEffort(svc.ReasoningEffort) {
		httpReq.Header.Set("X-reasoning-effort", svc.ReasoningEffort)
	}
	if svc.ReasoningFormat != "" && utils.IsValidReasoningFormat(svc.ReasoningFormat) {
		httpReq.Header.Set("X-reasoning-format", svc.ReasoningFormat)
	}

	// 创建HTTP客户端
	client, err := utils.CreateHTTPClient(svc.Proxy, time.Duration(svc.Timeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client error: %v", err)
	}

	// 发送请求
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("thinking service request error: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("thinking service returned status=%d, body=%s", resp.StatusCode, string(body))
	}

	// 解析响应
	var thinkResp api.ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&thinkResp); err != nil {
		return nil, fmt.Errorf("decode thinking response error: %v", err)
	}

	// 处理结果
	if len(thinkResp.Choices) == 0 {
		return nil, fmt.Errorf("thinking service returned empty choices")
	}

	// 提取内容
	content := thinkResp.Choices[0].Message.Content
	reasoningContent := ""

	// 提取推理内容
	if rc, ok := thinkResp.Choices[0].Message.ReasoningContent.(string); ok && rc != "" {
		reasoningContent = rc
	}

	return &ThinkingResponse{
		Content:          content,
		ReasoningContent: reasoningContent,
	}, nil
}

// prepareEnhancedRequest 准备增强请求
func (s *Server) prepareEnhancedRequest(originalReq *api.ChatCompletionRequest, thinkingResp *ThinkingResponse, svc config.ThinkingService) *api.ChatCompletionRequest {
	req := *originalReq

	// 构造思考过程消息
	var thinkingContent string
	if svc.Mode == "full" {
		thinkingContent = fmt.Sprintf(
			`Let me analyze this step by step:

%s

Based on this analysis, here's my response:
%s`,
			thinkingResp.ReasoningContent,
			thinkingResp.Content,
		)
	} else {
		thinkingContent = fmt.Sprintf(
			`My thinking process:

%s

Now, let me provide my response based on this analysis.`,
			thinkingResp.ReasoningContent,
		)
	}

	// 直接将思考过程追加到消息列表
	req.Messages = append(req.Messages, api.ChatCompletionMessage{
		Role:    "assistant",
		Content: thinkingContent,
	})

	// 保持用户设置的参数或使用默认值
	if req.Temperature == 0 {
		req.Temperature = 0.7
	}
	if req.TopP == 0 {
		req.TopP = 1.0
	}
	// max_tokens 为 0 或不设置时表示不限制长度
	// if req.MaxTokens == 0 {
	//     req.MaxTokens = 2000
	// }

	return &req
}

// prepareEnhancedRequest_system 准备增强请求，并修改System定义
func (s *Server) prepareEnhancedRequest_system(originalReq *api.ChatCompletionRequest, thinkingResp *ThinkingResponse, svc config.ThinkingService) *api.ChatCompletionRequest {
	req := *originalReq
	var systemPrompt string

	if svc.Mode == "full" {
		// 全量模式，合并推理内容和模型回复
		systemPrompt = fmt.Sprintf(
			`Consider the following detailed analysis (not shown to user):
%s

Provide a clear, concise response that incorporates insights from this analysis.`,
			thinkingResp.ReasoningContent,
		)
		if thinkingResp.Content != "" {
			systemPrompt += fmt.Sprintf("\n\nSuggested response:\n%s", thinkingResp.Content)
		}
	} else {
		// 标准模式，只使用推理内容
		systemPrompt = fmt.Sprintf(
			`Previous thinking process:
%s
Please consider the above thinking process in your response.`,
			thinkingResp.ReasoningContent,
		)
	}

	// 添加系统消息
	req.Messages = append([]api.ChatCompletionMessage{
		{Role: "system", Content: systemPrompt},
	}, req.Messages...)

	return &req
}

// forwardRequest 转发请求到目标通道
func (s *Server) forwardRequest(w http.ResponseWriter, ctx context.Context, req *api.ChatCompletionRequest, channel config.Channel) {
	// 序列化请求
	jsonData, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
		return
	}

	// 创建HTTP客户端
	client, err := utils.CreateHTTPClient(channel.Proxy, time.Duration(channel.Timeout)*time.Second)
	if err != nil {
		http.Error(w, "Failed to create HTTP client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, channel.GetFullURL(), bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	// 发送请求
	resp, err := client.Do(httpReq)
	if err != nil {
		http.Error(w, "Target service request error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制状态码
	w.WriteHeader(resp.StatusCode)

	// 复制响应头
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	// 复制响应体
	io.Copy(w, resp.Body)
}

// forwardModelsRequest 转发模型列表请求
func (s *Server) forwardModelsRequest(w http.ResponseWriter, ctx context.Context, req *api.ChatCompletionRequest, targetChannel config.Channel) {
	// 创建HTTP客户端
	client, err := utils.CreateHTTPClient(targetChannel.Proxy, time.Duration(targetChannel.Timeout)*time.Second)
	if err != nil {
		http.Error(w, "Failed to create HTTP client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetChannel.BaseURL+"/v1/models", nil)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 设置请求头
	httpReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	// 发送请求
	resp, err := client.Do(httpReq)
	if err != nil {
		http.Error(w, "Target service request error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制状态码
	w.WriteHeader(resp.StatusCode)

	// 复制响应头
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	// 复制响应体
	io.Copy(w, resp.Body)
}
