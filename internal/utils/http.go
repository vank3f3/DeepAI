package utils

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// CreateHTTPClient 创建一个HTTP客户端，支持代理设置
func CreateHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	transport := &http.Transport{
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
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		switch parsedURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(parsedURL)
		case "socks5":
			dialer, err := proxy.FromURL(parsedURL, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
			}
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", parsedURL.Scheme)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// MaskSensitiveHeaders 掩码敏感头信息，保护API密钥等敏感数据
func MaskSensitiveHeaders(headers http.Header) http.Header {
	masked := make(http.Header)
	for k, vals := range headers {
		if strings.ToLower(k) == "authorization" {
			masked[k] = []string{"Bearer ****"}
		} else {
			masked[k] = vals
		}
	}
	return masked
}

// IsValidReasoningEffort 验证推理努力有效性
func IsValidReasoningEffort(effort string) bool {
	switch strings.ToLower(effort) {
	case "low", "medium", "high":
		return true
	}
	return false
}

// IsValidReasoningFormat 验证推理格式有效性
func IsValidReasoningFormat(format string) bool {
	switch strings.ToLower(format) {
	case "parsed", "raw", "hidden":
		return true
	}
	return false
}
