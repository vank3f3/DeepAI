# DeepAI

一个支持OpenAI API兼容思考链(Thinking Chain)的代理服务器。

## 特性

- 支持OpenAI API标准格式
- 支持思考链流式输出
- 支持多通道配置
- 灵活的认证密钥设计
- 完整的错误处理和重试机制

## 快速开始

1. 下载对应平台的二进制文件
2. 创建配置文件 `config.yaml`
3. 运行服务

```bash
# Linux
chmod +x DeepAI-linux-amd64
./DeepAI-linux-amd64

# Windows
DeepAI-windows-amd64.exe
```

## 配置文件

```yaml
thinking_services:
  - id: 1
    name: "primary-thinking"
    base_url: "https://api.deepseek.com"
    api_key: "your-deepseek-key"
    timeout: 10
    retry: 3
    weight: 100

channels:
  "1":
    name: "deepseek-channel"
    base_url: "https://api.deepseek.com"
    key_prefix: "sk-deep"
    timeout: 30
    models:
      - "deepseek-chat"
      - "deepseek-code"
```

## API使用

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer deep-1-sk-xxxx" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }'
```

## 编译构建

本项目使用GitHub Actions自动构建，每次发布新标签时会自动编译Windows和Linux版本。

手动编译：

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o DeepAI-windows-amd64.exe

# Linux
GOOS=linux GOARCH=amd64 go build -o DeepAI-linux-amd64
```

## 许可证

MIT License
