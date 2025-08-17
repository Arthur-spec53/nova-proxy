package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"nova-proxy/internal/config"
	"nova-proxy/internal/protocol"
	"nova-proxy/internal/shaping"
	"nova-proxy/pkg/log"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	quic "github.com/qdeconinck/mp-quic"
	"github.com/sirupsen/logrus"
)

func main() {
	generateDefaultConfig()

	cfg, err := config.LoadClientConfig("client.json")
	if err != nil {
		log.Logger.Fatalf("Failed to load config: %v", err)
	}

	log.SetLevel(cfg.LogLevel)

	var profile *shaping.Profile
	profilePath := cfg.ShapingProfile
	// If the path is not absolute, treat it as relative to profiles directory
	if !filepath.IsAbs(profilePath) {
		profilePath = filepath.Join("/opt/nova-proxy/profiles", cfg.ShapingProfile)
	}
	profile, err = shaping.LoadProfile(profilePath)
	if err != nil {
		log.Logger.Fatalf("Failed to load shaping profile: %v", err)
	}
	log.Logger.Infof("Loaded shaping profile: %s", profile.Name)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Logger.Fatalf("Failed to start local listener: %v", err)
	}
	defer listener.Close()
	log.Logger.Infof("Client listening on %s", cfg.ListenAddr)

	// Setup config watcher for hot reload
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Logger.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	var mu sync.Mutex
	var currentProfile = profile

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Logger.Info("Config file modified, reloading...")
					newCfg, err := config.LoadClientConfig("client.json")
					if err != nil {
						log.Logger.Errorf("Failed to reload config: %v", err)
						continue
					}
					log.SetLevel(newCfg.LogLevel)
					newProfilePath := newCfg.ShapingProfile
					if !filepath.IsAbs(newProfilePath) {
						newProfilePath = filepath.Join("/opt/nova-proxy/profiles", newCfg.ShapingProfile)
					}
					newProfile, err := shaping.LoadProfile(newProfilePath)
					if err != nil {
						log.Logger.Errorf("Failed to load new shaping profile: %v", err)
						continue
					}
					mu.Lock()
					currentProfile = newProfile
					mu.Unlock()
					log.Logger.Infof("Reloaded config: log_level=%s, shaping_profile=%s", newCfg.LogLevel, newProfile.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Logger.Errorf("Watcher error: %v", err)
			}
		}
	}()

	err = watcher.Add("client.json")
	if err != nil {
		log.Logger.Fatalf("Failed to watch config file: %v", err)
	}

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Logger.Errorf("Failed to accept local connection: %v", err)
			continue
		}
		mu.Lock()
		go handleLocalConnection(localConn, cfg, currentProfile)
		mu.Unlock()
	}
}

func handleLocalConnection(localConn net.Conn, cfg *config.ClientConfig, profile *shaping.Profile) {
	defer localConn.Close()

	if cfg.PresharedKey == "" {
		log.Logger.Error("PresharedKey is not set in the config")
		return
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"nova-proxy"},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		log.Logger.Errorf("Failed to resolve remote address: %v", err)
		return
	}

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		log.Logger.Errorf("Failed to listen on UDP socket: %v", err)
		return
	}
	defer udpConn.Close()

	pconnMgr := &quic.PconnManager{}
	pconnMgr.SetAsClient()
	err = pconnMgr.Setup(udpConn, nil)
	if err != nil {
		log.Logger.Errorf("Failed to setup pconnManager: %v", err)
		return
	}

	quicConfig := &quic.Config{
		CreatePaths: true,
		KeepAlive:   true,
	}

	conn, err := quic.Dial(udpConn, udpAddr, cfg.RemoteAddr, tlsConf, quicConfig, pconnMgr)
	if err != nil {
		log.Logger.Errorf("Failed to dial proxy server with E-QUIC: %v", err)
		return
	}
	defer conn.Close(nil) // 调整为Close with error if needed

	stream, err := conn.OpenStreamSync()
	if err != nil {
		log.Logger.Errorf("Failed to open stream: %v", err)
		return
	}
	defer stream.Close()

	frame, err := handleSocks5Handshake(localConn)
	if err != nil {
		log.Logger.Warnf("SOCKS5 handshake failed: %v", err)
		return
	}

	if err := frame.Encode(stream); err != nil {
		log.Logger.Errorf("Failed to encode protocol frame: %v", err)
		return
	}

	log.Logger.WithFields(logrus.Fields{
		"target": frame.Host,
		"port":   frame.Port,
	}).Infof("Proxying local connection to %s:%d via %s (with E-QUIC and %s shaping)", frame.Host, frame.Port, cfg.RemoteAddr, profile.Name)

	go func() {
		io.Copy(stream, localConn)
	}()
	io.Copy(localConn, stream)
}

func handleSocks5Handshake(localConn net.Conn) (*protocol.Frame, error) {
	buf := make([]byte, 257)
	n, err := localConn.Read(buf)
	if err != nil || n < 2 {
		return nil, fmt.Errorf("failed to read SOCKS5 greeting: %w", err)
	}

	_, err = localConn.Write([]byte{0x05, 0x00})
	if err != nil {
		return nil, fmt.Errorf("failed to send SOCKS5 greeting response: %w", err)
	}

	n, err = localConn.Read(buf)
	if err != nil || n < 4 {
		return nil, fmt.Errorf("failed to read SOCKS5 request: %w", err)
	}

	req := buf[:n]
	if req[0] != 0x05 || req[1] != 0x01 {
		return nil, fmt.Errorf("unsupported SOCKS5 version or command")
	}

	frame := &protocol.Frame{Version: protocol.Version}
	addrType := req[3]
	var host string
	var port uint16
	offset := 4

	switch addrType {
	case 0x01:
		frame.AddrType = protocol.AddrTypeIPv4
		host = net.IP(req[offset : offset+4]).String()
		offset += 4
	case 0x03:
		frame.AddrType = protocol.AddrTypeDomain
		domainLen := int(req[offset])
		offset++
		host = string(req[offset : offset+domainLen])
		offset += domainLen
	case 0x04:
		frame.AddrType = protocol.AddrTypeIPv6
		host = net.IP(req[offset : offset+16]).String()
		offset += 16
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 address type: %d", addrType)
	}

	port = uint16(req[offset])<<8 | uint16(req[offset+1])
	frame.Host = host
	frame.Port = port

	_, err = localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, fmt.Errorf("failed to send SOCKS5 success response: %w", err)
	}

	return frame, nil
}

func generateDefaultConfig() {
	cfg := config.ClientConfig{
		RemoteAddr:     "127.0.0.1:4433",
		ListenAddr:     "127.0.0.1:1080",
		Password:       "your-secret-password",
		PresharedKey:   "a-very-secret-preshared-key-for-e-quic",
		ShapingProfile: "webrtc.json",
		LogLevel:       "info",
	}
	file, err := os.Create("client.json")
	if err != nil {
		log.Logger.Fatalf("Failed to create default config: %v", err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(cfg); err != nil {
		log.Logger.Fatalf("Failed to write default config: %v", err)
	}
}
