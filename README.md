好的,我来帮您完善一下 README.md 文件:

```markdown
# DeepAI

DeepAI 是一个支持 OpenAI API 兼容思考链 (Thinking Chain) 的代理服务器。它可以对接多个后端思考链/LLM 服务,同时提供一个标准的 OpenAI 兼容 API。

## 特性

- 兼容标准 OpenAI API,方便各种已有应用快速接入
- 支持对接多个后端思考链/LLM 服务,灵活切换
- 独特的 API-key 到后端服务映射机制,通过 key 前缀路由请求
- 合理利用 stream 机制,实时返回思考链内容,提升响应速度 
- 内置请求重试和熔断保护,提高服务可靠性

## 快速开始

1. 下载适用于您平台的可执行文件
2. 根据 `config-example.yaml` 创建配置文件 `config.yaml` 
3. 运行服务

### Linux

```bash
chmod +x DeepAI-linux-amd64
./DeepAI-linux-amd64
```

### Windows

```bash
DeepAI-windows-amd64.exe
```

## 配置说明

详细的配置项说明请参考 `config-example.yaml` 中的注释。

以下是一个最小化的配置文件示例:

```yaml
thinking_services:
  - name: "deepseek-thinking"
    base_url: "https://api.deepseek.com"
    api_key: "sk-xxxxxxxxxxxxxxxx"
    model: "deepseek-reasoner"
    
channels:
  "1":
    name: "deepseek-channel"
    base_url: "https://api.deepseek.com"
    timeout: 30
    proxy: "http://localhost:1080"
```

## API 使用示例

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
