package main

import (
	"context"
	"deepai/internal/config"
	"deepai/internal/server"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/viper"
)

// 配置加载与验证
func loadConfig() (*config.Config, error) {
	var configFile string
	flag.StringVar(&configFile, "config", "", "path to config file")
	flag.Parse()
	viper.SetConfigType("yaml")

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		ex, err := os.Executable()
		if err != nil {
			return nil, err
		}
		exePath := filepath.Dir(ex)
		defaultPaths := []string{
			filepath.Join(exePath, "config.yaml"),
			filepath.Join(exePath, "conf", "config.yaml"),
			"./config.yaml",
			"./conf/config.yaml",
		}
		if os.PathSeparator == '\\' {
			programData := os.Getenv("PROGRAMDATA")
			if programData != "" {
				defaultPaths = append(defaultPaths, filepath.Join(programData, "DeepAI", "config.yaml"))
			}
		} else {
			defaultPaths = append(defaultPaths, "/etc/deepai/config.yaml")
		}
		for _, p := range defaultPaths {
			viper.AddConfigPath(filepath.Dir(p))
			if strings.Contains(p, ".yaml") {
				viper.SetConfigName(strings.TrimSuffix(filepath.Base(p), ".yaml"))
			}
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config error: %v", err)
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("config validation error: %v", err)
	}
	return &cfg, nil
}

func validateConfig(config *config.Config) error {
	if len(config.ThinkingServices) == 0 {
		return fmt.Errorf("no thinking services configured")
	}
	if len(config.Channels) == 0 {
		return fmt.Errorf("no channels configured")
	}
	for i, svc := range config.ThinkingServices {
		if svc.BaseURL == "" {
			return fmt.Errorf("thinking service %s has empty baseURL", svc.Name)
		}
		if svc.APIKey == "" {
			return fmt.Errorf("thinking service %s has empty apiKey", svc.Name)
		}
		if svc.Timeout <= 0 {
			return fmt.Errorf("thinking service %s has invalid timeout", svc.Name)
		}
		if svc.Model == "" {
			return fmt.Errorf("thinking service %s has empty model", svc.Name)
		}
		if svc.Mode == "" {
			config.ThinkingServices[i].Mode = "standard"
		} else if svc.Mode != "standard" && svc.Mode != "full" {
			return fmt.Errorf("thinking service %s unknown mode=%s", svc.Name, svc.Mode)
		}
	}
	return nil
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Using config file: %s", viper.ConfigFileUsed())

	srv := server.NewServer(cfg)

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("start server error: %v", err)
		}
	}()
	log.Printf("Server started successfully")

	<-done
	log.Print("Server stopping...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Print("Server stopped")
}
