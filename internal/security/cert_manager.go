package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertificateType 证书类型
type CertificateType string

const (
	CertTypeServer CertificateType = "server"
	CertTypeClient CertificateType = "client"
	CertTypeCA     CertificateType = "ca"
)

// CertificateInfo 证书信息
type CertificateInfo struct {
	ID           string          `json:"id"`
	Type         CertificateType `json:"type"`
	Subject      string          `json:"subject"`
	Issuer       string          `json:"issuer"`
	SerialNumber string          `json:"serial_number"`
	NotBefore    time.Time       `json:"not_before"`
	NotAfter     time.Time       `json:"not_after"`
	DNSNames     []string        `json:"dns_names"`
	IPAddresses  []string        `json:"ip_addresses"`
	KeyUsage     []string        `json:"key_usage"`
	Fingerprint  string          `json:"fingerprint"`
	FilePath     string          `json:"file_path"`
	KeyPath      string          `json:"key_path"`
	Active       bool            `json:"active"`
	AutoRenew    bool            `json:"auto_renew"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// CertManagerConfig 证书管理器配置
type CertManagerConfig struct {
	CertStorePath    string        `json:"cert_store_path"`
	CAKeyPath        string        `json:"ca_key_path"`
	CACertPath       string        `json:"ca_cert_path"`
	DefaultKeySize   int           `json:"default_key_size"`
	DefaultValidDays int           `json:"default_valid_days"`
	RenewalThreshold time.Duration `json:"renewal_threshold"`
	AutoRenewal      bool          `json:"auto_renewal"`
	BackupEnabled    bool          `json:"backup_enabled"`
	BackupPath       string        `json:"backup_path"`
	OCSPEnabled      bool          `json:"ocsp_enabled"`
	CRLEnabled       bool          `json:"crl_enabled"`
}

// CertManager 证书管理器
type CertManager struct {
	config      *CertManagerConfig
	certs       map[string]*CertificateInfo
	caCert      *x509.Certificate
	caKey       interface{}
	mu          sync.RWMutex
	renewalCh   chan string
	stopCh      chan struct{}
	keyManager  *KeyManager
}

// NewCertManager 创建新的证书管理器
func NewCertManager(config *CertManagerConfig, keyManager *KeyManager) (*CertManager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// 设置默认值
	if config.DefaultKeySize == 0 {
		config.DefaultKeySize = 2048
	}
	if config.DefaultValidDays == 0 {
		config.DefaultValidDays = 365
	}
	if config.RenewalThreshold == 0 {
		config.RenewalThreshold = 30 * 24 * time.Hour // 30天
	}

	cm := &CertManager{
		config:     config,
		certs:      make(map[string]*CertificateInfo),
		renewalCh:  make(chan string, 100),
		stopCh:     make(chan struct{}),
		keyManager: keyManager,
	}

	// 加载CA证书和密钥
	if err := cm.loadCA(); err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	// 加载现有证书
	if err := cm.loadCertificates(); err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	// 启动自动续期协程
	if config.AutoRenewal {
		go cm.renewalWorker()
	}

	return cm, nil
}

// loadCA 加载CA证书和密钥
func (cm *CertManager) loadCA() error {
	// 检查CA证书和密钥是否存在
	if _, err := os.Stat(cm.config.CACertPath); os.IsNotExist(err) {
		// 生成新的CA证书
		return cm.generateCA()
	}

	// 加载CA证书
	certPEM, err := os.ReadFile(cm.config.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode CA certificate PEM")
	}

	cm.caCert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// 加载CA私钥
	keyPEM, err := os.ReadFile(cm.config.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode CA private key PEM")
	}

	cm.caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 尝试解析PKCS8格式
		cm.caKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key: %w", err)
		}
	}

	return nil
}

// generateCA 生成CA证书
func (cm *CertManager) generateCA() error {
	// 生成CA私钥
	caKey, err := rsa.GenerateKey(rand.Reader, cm.config.DefaultKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// 创建CA证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Nova Proxy CA"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{},
			PostalCode:    []string{},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(cm.config.DefaultValidDays*10) * 24 * time.Hour), // CA证书有效期更长
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 生成CA证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// 保存CA证书
	certOut, err := os.Create(cm.config.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// 保存CA私钥
	keyOut, err := os.OpenFile(cm.config.CAKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CA private key file: %w", err)
	}
	defer keyOut.Close()

	privKeyBytes := x509.MarshalPKCS1PrivateKey(caKey)

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	// 解析生成的证书
	cm.caCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	cm.caKey = caKey

	return nil
}

// GenerateCertificate 生成新证书
func (cm *CertManager) GenerateCertificate(certID string, certType CertificateType, dnsNames []string, ipAddresses []net.IP) (*CertificateInfo, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查证书是否已存在
	if _, exists := cm.certs[certID]; exists {
		return nil, fmt.Errorf("certificate with ID %s already exists", certID)
	}

	// 生成私钥
	privKey, err := rsa.GenerateKey(rand.Reader, cm.config.DefaultKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{"Nova Proxy"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(cm.config.DefaultValidDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	// 根据证书类型设置扩展密钥用法
	switch certType {
	case CertTypeServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case CertTypeClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case CertTypeCA:
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.IsCA = true
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, cm.caCert, &privKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// 解析生成的证书
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// 创建证书信息
	certInfo := &CertificateInfo{
		ID:           certID,
		Type:         certType,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		KeyUsage:     cm.getKeyUsageStrings(cert.KeyUsage),
		Fingerprint:  cm.calculateFingerprint(certDER),
		FilePath:     filepath.Join(cm.config.CertStorePath, certID+".crt"),
		KeyPath:      filepath.Join(cm.config.CertStorePath, certID+".key"),
		Active:       true,
		AutoRenew:    cm.config.AutoRenewal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// 转换IP地址为字符串
	for _, ip := range cert.IPAddresses {
		certInfo.IPAddresses = append(certInfo.IPAddresses, ip.String())
	}

	// 保存证书和私钥到文件
	if err := cm.saveCertificateToFile(certInfo, certDER, privKey); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// 存储证书信息
	cm.certs[certID] = certInfo

	// 保存证书元数据
	if err := cm.saveCertificateMetadata(certInfo); err != nil {
		return nil, fmt.Errorf("failed to save certificate metadata: %w", err)
	}

	return certInfo, nil
}

// GetCertificate 获取证书信息
func (cm *CertManager) GetCertificate(certID string) (*CertificateInfo, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	certInfo, exists := cm.certs[certID]
	if !exists {
		return nil, fmt.Errorf("certificate with ID %s not found", certID)
	}

	return certInfo, nil
}

// LoadTLSConfig 加载TLS配置
func (cm *CertManager) LoadTLSConfig(certID string) (*tls.Config, error) {
	certInfo, err := cm.GetCertificate(certID)
	if err != nil {
		return nil, err
	}

	// 加载证书和私钥
	cert, err := tls.LoadX509KeyPair(certInfo.FilePath, certInfo.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate pair: %w", err)
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	return tlsConfig, nil
}

// RenewCertificate 续期证书
func (cm *CertManager) RenewCertificate(certID string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	certInfo, exists := cm.certs[certID]
	if !exists {
		return fmt.Errorf("certificate with ID %s not found", certID)
	}

	// 备份旧证书
	if cm.config.BackupEnabled {
		if err := cm.backupCertificate(certInfo); err != nil {
			return fmt.Errorf("failed to backup certificate: %w", err)
		}
	}

	// 加载现有证书以获取DNS名称和IP地址
	certPEM, err := os.ReadFile(certInfo.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read existing certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode certificate PEM")
	}

	existingCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse existing certificate: %w", err)
	}

	// 生成新的私钥
	privKey, err := rsa.GenerateKey(rand.Reader, cm.config.DefaultKeySize)
	if err != nil {
		return fmt.Errorf("failed to generate new private key: %w", err)
	}

	// 创建新证书模板（保持相同的属性）
	template := x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().Unix()),
		Subject:         existingCert.Subject,
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Duration(cm.config.DefaultValidDays) * 24 * time.Hour),
		KeyUsage:        existingCert.KeyUsage,
		ExtKeyUsage:     existingCert.ExtKeyUsage,
		DNSNames:        existingCert.DNSNames,
		IPAddresses:     existingCert.IPAddresses,
		IsCA:            existingCert.IsCA,
		BasicConstraintsValid: existingCert.BasicConstraintsValid,
	}

	// 生成新证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, cm.caCert, &privKey.PublicKey, cm.caKey)
	if err != nil {
		return fmt.Errorf("failed to create renewed certificate: %w", err)
	}

	// 解析新证书
	newCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	// 更新证书信息
	certInfo.SerialNumber = newCert.SerialNumber.String()
	certInfo.NotBefore = newCert.NotBefore
	certInfo.NotAfter = newCert.NotAfter
	certInfo.Fingerprint = cm.calculateFingerprint(certDER)
	certInfo.UpdatedAt = time.Now()

	// 保存新证书和私钥
	if err := cm.saveCertificateToFile(certInfo, certDER, privKey); err != nil {
		return fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	// 保存更新的元数据
	if err := cm.saveCertificateMetadata(certInfo); err != nil {
		return fmt.Errorf("failed to save certificate metadata: %w", err)
	}

	return nil
}

// VerifyCertificate 验证证书
func (cm *CertManager) VerifyCertificate(certID string) error {
	certInfo, err := cm.GetCertificate(certID)
	if err != nil {
		return err
	}

	// 读取证书文件
	certPEM, err := os.ReadFile(certInfo.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 检查证书是否过期
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired on %v", cert.NotAfter)
	}

	// 检查证书是否还未生效
	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid until %v", cert.NotBefore)
	}

	// 验证证书链
	roots := x509.NewCertPool()
	roots.AddCert(cm.caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// loadCertificates 加载现有证书
func (cm *CertManager) loadCertificates() error {
	if _, err := os.Stat(cm.config.CertStorePath); os.IsNotExist(err) {
		return nil // 证书存储目录不存在，跳过加载
	}

	return filepath.WalkDir(cm.config.CertStorePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		// 读取证书元数据文件
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read certificate metadata %s: %w", path, err)
		}

		// 解析证书信息
		var certInfo CertificateInfo
		if err := json.Unmarshal(data, &certInfo); err != nil {
			return fmt.Errorf("failed to unmarshal certificate metadata %s: %w", path, err)
		}

		// 存储到内存
		cm.certs[certInfo.ID] = &certInfo

		return nil
	})
}

// saveCertificateToFile 保存证书和私钥到文件
func (cm *CertManager) saveCertificateToFile(certInfo *CertificateInfo, certDER []byte, privKey *rsa.PrivateKey) error {
	if err := os.MkdirAll(cm.config.CertStorePath, 0700); err != nil {
		return fmt.Errorf("failed to create certificate store directory: %w", err)
	}

	// 保存证书
	certOut, err := os.Create(certInfo.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// 保存私钥
	keyOut, err := os.OpenFile(certInfo.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer keyOut.Close()

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// saveCertificateMetadata 保存证书元数据
func (cm *CertManager) saveCertificateMetadata(certInfo *CertificateInfo) error {
	data, err := json.MarshalIndent(certInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal certificate metadata: %w", err)
	}

	metadataPath := filepath.Join(cm.config.CertStorePath, certInfo.ID+".json")
	if err := os.WriteFile(metadataPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write certificate metadata: %w", err)
	}

	return nil
}

// backupCertificate 备份证书
func (cm *CertManager) backupCertificate(certInfo *CertificateInfo) error {
	if !cm.config.BackupEnabled || cm.config.BackupPath == "" {
		return nil
	}

	backupDir := filepath.Join(cm.config.BackupPath, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// 备份证书文件
	certData, err := os.ReadFile(certInfo.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate for backup: %w", err)
	}

	certBackupPath := filepath.Join(backupDir, certInfo.ID+".crt.bak")
	if err := os.WriteFile(certBackupPath, certData, 0600); err != nil {
		return fmt.Errorf("failed to backup certificate: %w", err)
	}

	// 备份私钥文件
	keyData, err := os.ReadFile(certInfo.KeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key for backup: %w", err)
	}

	keyBackupPath := filepath.Join(backupDir, certInfo.ID+".key.bak")
	if err := os.WriteFile(keyBackupPath, keyData, 0600); err != nil {
		return fmt.Errorf("failed to backup private key: %w", err)
	}

	return nil
}

// renewalWorker 证书续期工作协程
func (cm *CertManager) renewalWorker() {
	ticker := time.NewTicker(24 * time.Hour) // 每天检查一次
	defer ticker.Stop()

	for {
		select {
		case certID := <-cm.renewalCh:
			if err := cm.RenewCertificate(certID); err != nil {
				// 记录错误但不停止工作协程
				fmt.Printf("Failed to renew certificate %s: %v\n", certID, err)
			}
		case <-ticker.C:
			// 定期检查需要续期的证书
			cm.checkRenewalDue()
		case <-cm.stopCh:
			return
		}
	}
}

// checkRenewalDue 检查需要续期的证书
func (cm *CertManager) checkRenewalDue() {
	cm.mu.RLock()
	now := time.Now()
	for certID, certInfo := range cm.certs {
		if certInfo.Active && certInfo.AutoRenew {
			// 检查是否在续期阈值内
			if now.Add(cm.config.RenewalThreshold).After(certInfo.NotAfter) {
				select {
				case cm.renewalCh <- certID:
				default:
					// 续期队列已满，跳过
				}
			}
		}
	}
	cm.mu.RUnlock()
}

// getKeyUsageStrings 获取密钥用法字符串
func (cm *CertManager) getKeyUsageStrings(keyUsage x509.KeyUsage) []string {
	var usages []string

	if keyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if keyUsage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if keyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if keyUsage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if keyUsage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if keyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if keyUsage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if keyUsage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if keyUsage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// calculateFingerprint 计算证书指纹
func (cm *CertManager) calculateFingerprint(certDER []byte) string {
	return fmt.Sprintf("%x", certDER[:20]) // 简化的指纹计算
}

// ListCertificates 列出所有证书
func (cm *CertManager) ListCertificates() []CertificateInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var certs []CertificateInfo
	for _, certInfo := range cm.certs {
		certs = append(certs, *certInfo)
	}

	return certs
}

// DeleteCertificate 删除证书
func (cm *CertManager) DeleteCertificate(certID string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	certInfo, exists := cm.certs[certID]
	if !exists {
		return fmt.Errorf("certificate with ID %s not found", certID)
	}

	// 备份证书（如果启用）
	if cm.config.BackupEnabled {
		if err := cm.backupCertificate(certInfo); err != nil {
			return fmt.Errorf("failed to backup certificate before deletion: %w", err)
		}
	}

	// 删除证书文件
	if err := os.Remove(certInfo.FilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete certificate file: %w", err)
	}

	// 删除私钥文件
	if err := os.Remove(certInfo.KeyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete private key file: %w", err)
	}

	// 删除元数据文件
	metadataPath := filepath.Join(cm.config.CertStorePath, certID+".json")
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete certificate metadata: %w", err)
	}

	// 从内存中删除
	delete(cm.certs, certID)

	return nil
}

// Close 关闭证书管理器
func (cm *CertManager) Close() error {
	close(cm.stopCh)
	return nil
}