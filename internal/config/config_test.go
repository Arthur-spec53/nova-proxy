package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadServerConfig(t *testing.T) {
	content := `{
		"listen_addr": "0.0.0.0:8888",
		"cert_file": "server.crt",
		"key_file": "server.key",
		"password": "server_password"
	}`
	tmpfile, err := os.CreateTemp("", "server.*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	cfg, err := LoadServerConfig(tmpfile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "0.0.0.0:8888", cfg.ListenAddr)
	assert.Equal(t, "server.crt", cfg.CertFile)
	assert.Equal(t, "server.key", cfg.KeyFile)
	assert.Equal(t, "server_password", cfg.Password)
}

func TestLoadClientConfig(t *testing.T) {
	content := `{
		"remote_addr": "server.com:8888",
		"listen_addr": "127.0.0.1:1080",
		"password": "client_password"
	}`
	tmpfile, err := os.CreateTemp("", "client.*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	cfg, err := LoadClientConfig(tmpfile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "server.com:8888", cfg.RemoteAddr)
	assert.Equal(t, "127.0.0.1:1080", cfg.ListenAddr)
	assert.Equal(t, "client_password", cfg.Password)
}
