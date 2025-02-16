# DeepAI

DeepAI 是一个代理服务器，旨在通过整合“思考链”过程来增强大型语言模型 (LLM) 的交互体验。它充当中间层，接收标准的 OpenAI API 兼容请求，利用独立的“思考服务”生成推理过程，然后将增强后的请求转发到您选择的 LLM 后端。这使得您获得的响应不仅由 LLM 生成，而且还基于预先的推理分析，从而可能产生更具洞察力和连贯性的输出。

## 特性

- **OpenAI API 兼容性:**  无缝集成为 OpenAI API 设计的应用程序。 DeepAI 支持 `/v1/chat/completions` 和 `/v1/models` 端点，确保轻松接入。
- **思考链增强:**  在将用户请求发送到最终 LLM 之前，自动使用专门的“思考服务”生成的推理过程来丰富请求内容。
- **灵活的后端支持:**  配置多个后端 LLM 服务（“渠道”）和思考链服务。根据您的需求轻松切换或将请求路由到不同的服务。
- **API 密钥路由:**  采用独特的 API 密钥路由机制。API 密钥前缀决定了哪个后端渠道将处理请求，从而为服务使用提供精细的控制。
- **流式和标准响应:**  支持聊天完成的流式和标准响应，为不同的应用程序需求提供灵活性。思考过程的实时流式传输增强了用户体验。
- **加权思考服务选择:**  实现加权随机选择算法，用于从多个思考服务中进行选择，从而允许基于服务权重进行负载均衡和优先级排序。
- **代理支持:**  支持 HTTP、HTTPS 和 SOCKS5 代理，用于连接思考服务和后端 LLM 渠道，适应各种网络环境。
- **强大的日志记录:**  全面的请求日志记录，包括唯一的请求 ID、时间戳和内容日志记录（在调试模式下），以便进行有效的监控和调试。
- **优雅关机:**  确保在接收到中断信号时平稳地关闭服务器，防止数据丢失并确保干净的退出。

## 快速开始

1. **下载可执行文件:** 从 [发布版本](https://github.com/BlueSkyXN/DeepAI/releases) 部分下载适用于您平台的预编译可执行文件（或从源代码构建 - 请参阅下文）。

2. **配置:** 基于仓库中提供的 `config-example.yaml` 模板创建 `config.yaml` 配置文件。 **重要提示:** 您必须在此文件中配置您的思考服务和渠道。

3. **运行 DeepAI:** 执行下载的二进制文件。

### Linux

```bash
chmod +x DeepAI-linux-amd64  # 或适用于您架构的二进制文件
./DeepAI-linux-amd64
```

### macOS

```bash
chmod +x DeepAI-darwin-amd64 # 或适用于您架构的二进制文件
./DeepAI-darwin-amd64
```

### Windows

```bash
DeepAI-windows-amd64.exe # 或适用于您架构的二进制文件
```

## 配置说明

DeepAI 通过 `config.yaml` 文件进行配置。仓库中提供了一个带有详细注释的 `config-example.yaml` 模板，以指导您完成配置选项。

**最小化配置示例 (`config.yaml`):**

```yaml
thinking_services:
  - name: "deepseek-thinking"
    base_url: "https://api.deepseek.com" # 您的思考服务 API 的 Base URL
    api_path: "/v1/chat/completions"     # 聊天完成的 API 路径（如果与 /v1/chat/completions 不同）
    api_key: "sk-xxxxxxxxxxxxxxxx"       # 您的思考服务的 API 密钥
    model: "deepseek-reasoner"          # 用于思考的模型

channels:
  "1": # 渠道 ID（在 API 密钥前缀中使用）
    name: "deepseek-channel"
    base_url: "https://api.deepseek.com" # 您的目标 LLM API 的 Base URL
    api_path: "/v1/chat/completions"     # 聊天完成的 API 路径（如果与 /v1/chat/completions 不同）
    timeout: 30                           # 请求超时时间，单位秒
    proxy: "http://localhost:1080"        # 此渠道的可选代理（例如，用于测试）
```

**主要配置部分:**

* **`thinking_services`:** 定义一个或多个思考服务。每个服务都需要：
    * `name`: 服务的描述性名称。
    * `base_url`: 思考服务 API 的 Base URL。
    * `api_key`: 用于向思考服务进行身份验证的 API 密钥。
    * `model`: 用于生成推理过程的模型。
    * `weight`: 加权随机选择的权重（权重越高，被选中的概率越高）。
* **`channels`:** 定义后端 LLM 渠道。每个渠道由唯一的 ID（字符串键）标识，并需要：
    * `name`: 渠道的描述性名称。
    * `base_url`: 目标 LLM API 的 Base URL。
    * `timeout`: 发送到此渠道的请求超时时间，单位秒。
    * `proxy`: 发送到此渠道的请求的可选代理 URL。
* **`global`:** 代理服务器的全局设置，包括服务器端口、超时时间、日志配置和代理设置。


## API 使用示例

向 DeepAI 发送聊天完成请求，包括 `Authorization` 标头 Bearer 令牌中的渠道 ID。

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer deep-1-sk-xxxx"  # 'deep-1-' 前缀路由到 ID 为 "1" 的渠道
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",             # 目标 LLM 渠道的模型
    "messages": [{"role": "user", "content": "你好"}],
    "stream": true                       # 可选：设置为 true 以获得流式响应
  }'
```

**API 密钥格式:**

`Authorization` 标头使用 Bearer 令牌，格式如下：

`Bearer <api_provider>-<channel_id>-<your_real_api_key>`

* `<api_provider>`:  `deep` 或 `openai`（当前支持的前缀，用于内部识别，可以扩展）。
* `<channel_id>`:  在您的 `config.yaml` 中定义的渠道的 ID（例如，`1`、`2`、`my-channel`）。
* `<your_real_api_key>`: 您用于目标 LLM 服务的实际 API 密钥。

**API 密钥示例:**

* `Bearer deep-1-sk-xxxxxxxxxxxxxxxx` (使用渠道 "1" 和 DeepSeek API)
* `Bearer openai-2-sk-yyyyyyyyyyyyyyyy` (使用渠道 "2" 和 OpenAI API - 如果已配置)

