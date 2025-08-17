package benchmark

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"nova-proxy/internal/shaping"
	"nova-proxy/internal/transport"
	"sync"
	"testing"
	"time"

	quic "github.com/qdeconinck/mp-quic"
)

func setReceiveBuffer(conn *net.UDPConn) {
	if err := conn.SetReadBuffer(4 * 1024 * 1024); err != nil {
		panic("Failed to set receive buffer: " + err.Error())
	}
}

const (
	payloadSize = 1 * 1024 * 1024 // 1 MB
)

// runFileServer serves a large payload to any connecting client.
func runFileServer(b *testing.B, wg *sync.WaitGroup, serverAddr string, key []byte, profile *shaping.Profile, tlsConf *tls.Config, quicConf *quic.Config, payload []byte, shutdown chan struct{}, enableShaper bool) {
	defer wg.Done()

	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		b.Fatalf("Failed to resolve UDP addr: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		b.Fatalf("Server: ListenUDP failed: %v", err)
	}
	defer udpConn.Close()
	setReceiveBuffer(udpConn)

	equicTransport := transport.NewEQUICTransport(udpConn, key)
	var shaper *shaping.Shaper
	if enableShaper {
		shaper = shaping.NewShaper(equicTransport.WriteToNetwork, profile, nil) // Server side, no remoteAddr
		equicTransport.SetShaper(shaper)
	}

	listener, err := quic.Listen(equicTransport, tlsConf, quicConf)
	if err != nil {
		b.Errorf("Server: quic.Listen failed: %v", err)
		return
	}
	defer func() {
		fmt.Println("server defer closing listener")
		listener.Close()
		if shaper != nil {
			shaper.Stop()
		}
	}()

	fmt.Println("server listening")

	go func() {
		fmt.Println("server shutdown goroutine waiting")
		<-shutdown
		fmt.Println("server shutdown signaled, closing listener")
		listener.Close()
	}()

	fmt.Println("server accepting connection")
	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("server accept conn error:", err)
		return
	}
	fmt.Println("server accepted connection")
	defer func() {
		fmt.Println("server defer closing conn")
		conn.Close(nil)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		fmt.Println("server defer cancel")
		cancel()
	}()
	go func() {
		fmt.Println("server conn shutdown goroutine waiting")
		<-shutdown
		fmt.Println("server conn shutdown signaled, canceling and closing conn")
		cancel()
		conn.Close(nil)
		fmt.Println("server conn closed")
	}()

	fmt.Println("server starting stream loop")
	var streamWg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			fmt.Println("server stream loop exiting due to context done")
			streamWg.Wait()
			return
		default:
			fmt.Println("server waiting for stream")
			stream, err := conn.AcceptStream()
			if err != nil {
				fmt.Println("server accept stream error:", err)
				break
			}
			fmt.Println("server accepted stream")
			streamWg.Add(1)
			go func(s quic.Stream) {
				defer streamWg.Done()
				fmt.Println("server reading from stream")
				_, err := io.Copy(io.Discard, s)
				if err != nil {
					fmt.Println("server read error:", err)
				}
				fmt.Println("server read done")
			}(stream)
			streamWg.Add(1)
			go func(s quic.Stream) {
				defer streamWg.Done()
				fmt.Println("server writing payload")
				_, err := s.Write(payload)
				if err != nil {
					fmt.Println("server write error:", err)
				}
				fmt.Println("server wrote payload")
				fmt.Println("server closing stream write")
				s.Close()
			}(stream)
		}
	}
}

func BenchmarkDownloadThroughput(b *testing.B) {
	key := sha256.Sum256([]byte("benchmark-secret-key"))
	profile, err := shaping.LoadProfile("../profiles/benchmark.json")
	if err != nil {
		b.Fatalf("Failed to load profile: %v", err)
	}
	serverAddr := "127.0.0.1:54321"

	serverTlsConf, clientTlsConf, err := generateTestTLSConfigs(serverAddr)
	if err != nil {
		b.Fatalf("Failed to generate TLS configs: %v", err)
	}

	quicConf := &quic.Config{
		IdleTimeout: time.Minute,
	}

	payload := make([]byte, payloadSize)
	rand.Read(payload)

	var wg sync.WaitGroup
	wg.Add(1)
	shutdown := make(chan struct{})
	go func() {
		fmt.Println("starting server")
		runFileServer(b, &wg, serverAddr, key[:], profile, serverTlsConf, quicConf, payload, shutdown, false) // 禁用shaper
		fmt.Println("server exited")
	}()
	time.Sleep(100 * time.Millisecond)

	udpServerAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
	clientAddr, _ := net.ResolveUDPAddr("udp", ":0")
	udpConn, _ := net.ListenUDP("udp", clientAddr)
	defer udpConn.Close()
	setReceiveBuffer(udpConn)

	equicTransport := transport.NewEQUICTransport(udpConn, key[:])
	var clientShaper *shaping.Shaper
	if false { // 禁用客户端shaper
		clientShaper = shaping.NewShaper(equicTransport.WriteToNetwork, profile, udpServerAddr)
		equicTransport.SetShaper(clientShaper)
	}

	conn, err := quic.Dial(equicTransport, udpServerAddr, "localhost", clientTlsConf, quicConf, nil)
	if err != nil {
		b.Fatalf("Client: Dial failed: %v", err)
	}
	fmt.Println("client dialed")
	defer func() {
		fmt.Println("client defer closing conn")
		conn.Close(nil)
		if clientShaper != nil {
			clientShaper.Stop()
		}
	}()

	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()

	var clientWg sync.WaitGroup
	const numStreams = 10
	for i := 0; i < b.N; i++ {
		for j := 0; j < numStreams; j++ {
			clientWg.Add(1)
			go func() {
				defer clientWg.Done()
				fmt.Println("client opening stream")
				stream, err := conn.OpenStreamSync()
				if err != nil {
					b.Fatalf("Client: OpenStreamSync failed: %v", err)
				}
				fmt.Println("client opened stream")
				fmt.Println("client sending request")
				_, err = stream.Write([]byte("request"))
				if err != nil {
					b.Fatalf("Client write failed: %v", err)
				}
				fmt.Println("client request sent")
				fmt.Println("client reading from stream")
				_, err = io.Copy(io.Discard, stream)
				if err != nil {
					b.Fatalf("Read failed: %v", err)
				}
				fmt.Println("client read done")
				stream.Close()
				fmt.Println("client closed stream")
			}()
		}
		clientWg.Wait()
	}

	b.StopTimer()
	clientWg.Wait()
	fmt.Println("client loop done, closing shutdown")
	close(shutdown)
	fmt.Println("client closing conn")
	conn.Close(nil)
	fmt.Println("client waiting for wg")
	wg.Wait()
	fmt.Println("client wg done")
}

func generateTestTLSConfigs(serverName string) (*tls.Config, *tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"nova-proxy-benchmark"},
	}

	clientConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"nova-proxy-benchmark"},
	}

	return serverConfig, clientConfig, nil
}
