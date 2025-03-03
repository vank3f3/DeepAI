package logger

import (
	"deepai/internal/config"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RequestLogger 请求日志记录器
type RequestLogger struct {
	RequestID string
	Model     string
	StartTime time.Time
	logs      []string
	config    *config.Config
}

// NewRequestLogger 创建新的请求日志记录器
func NewRequestLogger(config *config.Config) *RequestLogger {
	return &RequestLogger{
		RequestID: uuid.New().String(),
		StartTime: time.Now(),
		logs:      make([]string, 0),
		config:    config,
	}
}

// Log 记录日志
func (l *RequestLogger) Log(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.logs = append(l.logs, fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), msg))
	log.Printf("[RequestID: %s] %s", l.RequestID, msg)
}

// LogContent 记录内容
func (l *RequestLogger) LogContent(contentType string, content interface{}, maxLength int) {
	if !l.config.Global.Log.Debug.Enabled {
		return
	}
	sanitizedContent := SanitizeJSON(content)
	truncatedContent := TruncateContent(sanitizedContent, maxLength)
	l.Log("%s Content:\n%s", contentType, truncatedContent)
}

// TruncateContent 截断内容
func TruncateContent(content string, maxLength int) string {
	if len(content) <= maxLength {
		return content
	}
	return content[:maxLength] + "... (truncated)"
}

// SanitizeJSON 清理JSON中的敏感信息
func SanitizeJSON(data interface{}) string {
	sanitized, err := json.Marshal(data)
	if err != nil {
		return "Failed to marshal JSON"
	}
	content := string(sanitized)
	sensitivePattern := `"api_key":\s*"[^"]*"`
	content = regexp.MustCompile(sensitivePattern).ReplaceAllString(content, `"api_key":"****"`)
	return content
}

// 工具函数
func ExtractRealAPIKey(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 3 && (parts[0] == "deep" || parts[0] == "openai") {
		return strings.Join(parts[2:], "-")
	}
	return fullKey
}

func ExtractChannelID(fullKey string) string {
	parts := strings.Split(fullKey, "-")
	if len(parts) >= 2 && (parts[0] == "deep" || parts[0] == "openai") {
		return parts[1]
	}
	return "1" // 默认渠道
}

func LogAPIKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
