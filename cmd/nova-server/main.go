package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/pprof"
	"nova-proxy/internal/config"
	"nova-proxy/internal/metrics"
	"nova-proxy/internal/protocol"
	"nova-proxy/internal/shaping"
	"nova-proxy/internal/transport"
	"nova-proxy/pkg/log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	quic "github.com/qdeconinck/mp-quic"
	"golang.org/x/sys/unix"
)

func main() {
	generateDefaultConfig()

	cfg, err := config.LoadServerConfig("server.json")
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

	if cfg.PresharedKey == "" {
		log.Logger.Fatal("PresharedKey is not set in the config")
	}
	e_quic_key := sha256.Sum256([]byte(cfg.PresharedKey))

	tlsConf, err := generateTLSConfig()
	if err != nil {
		log.Logger.Fatalf("Failed to generate TLS config: %v", err)
	}

	udpConn, err := net.ListenPacket("udp", cfg.ListenAddr)
	if err != nil {
		log.Logger.Fatalf("Failed to listen on UDP socket: %v", err)
	}
	defer udpConn.Close()

	// Manually set UDP buffer sizes
	if udpC, ok := udpConn.(*net.UDPConn); ok {
		fd, err := udpC.File()
		if err != nil {
			log.Logger.Warnf("Failed to get file descriptor: %v", err)
		} else {
			if err := unix.SetsockoptInt(int(fd.Fd()), unix.SOL_SOCKET, unix.SO_RCVBUF, 3*1024*1024); err != nil {
				log.Logger.Warnf("Failed to set SO_RCVBUF: %v", err)
			}
			if err := unix.SetsockoptInt(int(fd.Fd()), unix.SOL_SOCKET, unix.SO_SNDBUF, 3*1024*1024); err != nil {
				log.Logger.Warnf("Failed to set SO_SNDBUF: %v", err)
			}
		}
	}

	// 1. Create the transport
	e_quic_transport := transport.NewEQUICTransport(udpConn, e_quic_key[:])
	// 2. Create the shaper, passing the transport's actual write method
	var mu sync.Mutex
	var currentShaper *shaping.Shaper
	currentShaper = shaping.NewShaper(e_quic_transport.WriteToNetwork, profile, nil) // Server shaper has nil remoteAddr
	// 3. Attach the shaper to the transport
	e_quic_transport.SetShaper(currentShaper)

	quicConfig := &quic.Config{
		CreatePaths: true,
		KeepAlive:   true,
	}

	listener, err := quic.Listen(e_quic_transport, tlsConf, quicConfig)
	if err != nil {
		log.Logger.Fatalf("Failed to start QUIC listener: %v", err)
	}

	log.Logger.Infof("Server listening on %s (with E-QUIC and %s shaping)", cfg.ListenAddr, profile.Name)

	// Start Prometheus metrics endpoint
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/debug/pprof/", pprof.Index)
		if err := http.ListenAndServe(":2112", nil); err != nil {
			log.Logger.Fatalf("Failed to start metrics server: %v", err)
		}
	}()

	// Setup config watcher for hot reload
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Logger.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Logger.Info("Config file modified, reloading...")
					newCfg, err := config.LoadServerConfig("server.json")
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
					oldShaper := currentShaper
					currentShaper = shaping.NewShaper(e_quic_transport.WriteToNetwork, newProfile, nil)
					e_quic_transport.SetShaper(currentShaper)
					oldShaper.Stop()
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

	err = watcher.Add("server.json")
	if err != nil {
		log.Logger.Fatalf("Failed to watch config file: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Logger.Errorf("Failed to accept connection: %v", err)
			continue
		}
		log.Logger.Infof("Accepted new connection from %s", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Session) {
	defer conn.Close(nil)

	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	stream, err := conn.AcceptStream()
	if err != nil {
		log.Logger.Errorf("Failed to accept stream: %v", err)
		metrics.ErrorCount.WithLabelValues("accept_stream").Inc()
		return
	}
	defer stream.Close()

	frame, err := protocol.Decode(stream)
	if err != nil {
		log.Logger.Warnf("Failed to decode protocol frame: %v", err)
		metrics.ErrorCount.WithLabelValues("decode_frame").Inc()
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", frame.Host, frame.Port)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Logger.Errorf("Failed to connect to target %s: %v", targetAddr, err)
		metrics.ErrorCount.WithLabelValues("dial_target").Inc()
		return
	}
	defer targetConn.Close()

	log.Logger.WithField("target", targetAddr).Infof("Proxying for %s", targetAddr)

	go func() {
		n, err := io.Copy(targetConn, stream)
		if err != nil {
			log.Logger.Errorf("Copy from stream to target failed: %v", err)
			metrics.ErrorCount.WithLabelValues("copy_stream_to_target").Inc()
		}
		metrics.ThroughputBytes.WithLabelValues("upstream").Add(float64(n))
	}()
	n, err := io.Copy(stream, targetConn)
	if err != nil {
		log.Logger.Errorf("Copy from target to stream failed: %v", err)
		metrics.ErrorCount.WithLabelValues("copy_target_to_stream").Inc()
	}
	metrics.ThroughputBytes.WithLabelValues("downstream").Add(float64(n))
}

func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"nova-proxy"},
	}, nil
}

func generateDefaultConfig() {
	cfg := config.ServerConfig{
		ListenAddr:     "0.0.0.0:4433",
		CertFile:       "cert.pem",
		KeyFile:        "key.pem",
		Password:       "your-secret-password",
		PresharedKey:   "a-very-secret-preshared-key-for-e-quic",
		ShapingProfile: "webrtc.json",
		LogLevel:       "info",
	}
	file, err := os.Create("server.json")
	if err != nil {
		log.Logger.Fatalf("Failed to create default config: %v", err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(cfg); err != nil {
		log.Logger.Fatalf("Failed to write default config: %v", err)
	}
}
