package config

// 配置结构
type Config struct {
	ThinkingServices []ThinkingService  `mapstructure:"thinking_services"`
	Channels         map[string]Channel `mapstructure:"channels"`
	Global           GlobalConfig       `mapstructure:"global"`
}

type ThinkingService struct {
	ID                    int      `mapstructure:"id"`
	Name                  string   `mapstructure:"name"`
	Model                 string   `mapstructure:"model"`
	BaseURL               string   `mapstructure:"base_url"`
	APIPath               string   `mapstructure:"api_path"`
	APIKey                string   `mapstructure:"api_key"`
	Timeout               int      `mapstructure:"timeout"`
	Retry                 int      `mapstructure:"retry"`
	Weight                int      `mapstructure:"weight"`
	Proxy                 string   `mapstructure:"proxy"`
	Mode                  string   `mapstructure:"mode"` // "standard" 或 "full"
	ReasoningEffort       string   `mapstructure:"reasoning_effort"`
	ReasoningFormat       string   `mapstructure:"reasoning_format"`
	Temperature           *float64 `mapstructure:"temperature"`
	MaxTokens             *int     `mapstructure:"max_tokens"`
	TopP                  *float64 `mapstructure:"top_p"`
	ForceStopDeepThinking bool     `mapstructure:"force_stop_deep_thinking"` // 配置项：标准模式下遇到 content 时是否立即停止
}

// GetFullURL 返回完整URL
func (s *ThinkingService) GetFullURL() string {
	return s.BaseURL + s.APIPath
}

type Channel struct {
	Name    string `mapstructure:"name"`
	BaseURL string `mapstructure:"base_url"`
	APIPath string `mapstructure:"api_path"`
	Timeout int    `mapstructure:"timeout"`
	Proxy   string `mapstructure:"proxy"`
}

// GetFullURL 返回完整URL
func (c *Channel) GetFullURL() string {
	return c.BaseURL + c.APIPath
}

type LogConfig struct {
	Level    string      `mapstructure:"level"`
	Format   string      `mapstructure:"format"`
	Output   string      `mapstructure:"output"`
	FilePath string      `mapstructure:"file_path"`
	Debug    DebugConfig `mapstructure:"debug"`
}

type DebugConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	PrintRequest     bool `mapstructure:"print_request"`
	PrintResponse    bool `mapstructure:"print_response"`
	MaxContentLength int  `mapstructure:"max_content_length"`
}

type ProxyConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Default       string `mapstructure:"default"`
	AllowInsecure bool   `mapstructure:"allow_insecure"`
}

type GlobalConfig struct {
	MaxRetries     int `mapstructure:"max_retries"`
	DefaultTimeout int `mapstructure:"default_timeout"`
	ErrorCodes     struct {
		RetryOn []int `mapstructure:"retry_on"`
	} `mapstructure:"error_codes"`
	Log         LogConfig      `mapstructure:"log"`
	Server      ServerConfig   `mapstructure:"server"`
	Proxy       ProxyConfig    `mapstructure:"proxy"`
	ConfigPaths []string       `mapstructure:"config_paths"`
	Thinking    ThinkingConfig `mapstructure:"thinking"`
}

type ServerConfig struct {
	Port         int    `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	IdleTimeout  int    `mapstructure:"idle_timeout"`
}

type ThinkingConfig struct {
	Enabled          bool `mapstructure:"enabled"`
	AddToAllRequests bool `mapstructure:"add_to_all_requests"`
	Timeout          int  `mapstructure:"timeout"`
}
