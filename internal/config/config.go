package config

import (
	"encoding/json"
	"os"
)

// ServerConfig holds the configuration for the proxy server.
type ServerConfig struct {
	ListenAddr      string `json:"listen_addr"`
	CertFile        string `json:"cert_file"`
	KeyFile         string `json:"key_file"`
	Password        string `json:"password"`
	PresharedKey    string `json:"preshared_key"` // Key for E-QUIC layer
	ShapingProfile  string `json:"shaping_profile"`
	LogLevel        string `json:"log_level"`
}

// ClientConfig holds the configuration for the proxy client.
type ClientConfig struct {
	RemoteAddr      string `json:"remote_addr"`
	ListenAddr      string `json:"listen_addr"`
	Password        string `json:"password"`
	PresharedKey    string `json:"preshared_key"` // Key for E-QUIC layer
	ShapingProfile  string `json:"shaping_profile"`
	LogLevel        string `json:"log_level"`
}

// LoadServerConfig loads server configuration from a JSON file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &ServerConfig{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadClientConfig loads client configuration from a JSON file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &ClientConfig{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
