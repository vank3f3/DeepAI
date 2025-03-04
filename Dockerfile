# 使用多阶段构建
# 第一阶段：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git

# 复制 go.mod 和 go.sum 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -o deepai

# 第二阶段：运行阶段
FROM alpine:latest

# 安装 CA 证书，用于 HTTPS 请求
RUN apk --no-cache add ca-certificates tzdata

# 设置时区
ENV TZ=Asia/Shanghai

# 创建非 root 用户
RUN adduser -D -h /app appuser

# 创建必要的目录
RUN mkdir -p /app/conf /app/logs \
    && chown -R appuser:appuser /app

# 切换到非 root 用户
USER appuser

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/deepai .

# 复制配置文件
COPY config-example.yaml /app/config.yaml

# 创建配置文件目录的挂载点
VOLUME ["/app/logs"]

# 暴露端口
EXPOSE 8888

# 设置健康检查
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget -q --spider http://localhost:8888/health || exit 1

# 启动命令
ENTRYPOINT ["./deepai"]
CMD ["--config", "/app/config.yaml"]
