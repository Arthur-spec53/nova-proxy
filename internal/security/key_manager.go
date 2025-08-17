package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// KeyType 定义密钥类型
type KeyType string

const (
	KeyTypeAES256    KeyType = "aes256"
	KeyTypeChaCha20  KeyType = "chacha20"
	KeyTypeHMAC      KeyType = "hmac"
	KeyTypePreShared KeyType = "preshared"
)

// KeyMetadata 密钥元数据
type KeyMetadata struct {
	ID          string    `json:"id"`
	Type        KeyType   `json:"type"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RotationDue time.Time `json:"rotation_due"`
	Version     int       `json:"version"`
	Active      bool      `json:"active"`
	UsageCount  int64     `json:"usage_count"`
}

// EncryptedKey 加密存储的密钥
type EncryptedKey struct {
	Metadata   KeyMetadata `json:"metadata"`
	Ciphertext string      `json:"ciphertext"`
	Nonce      string      `json:"nonce"`
	Salt       string      `json:"salt"`
}

// KeyManagerConfig 密钥管理器配置
type KeyManagerConfig struct {
	KeyStorePath     string        `json:"key_store_path"`
	MasterPassword   string        `json:"master_password"`
	RotationInterval time.Duration `json:"rotation_interval"`
	KeyExpiry        time.Duration `json:"key_expiry"`
	BackupEnabled    bool          `json:"backup_enabled"`
	BackupPath       string        `json:"backup_path"`
	EncryptionAlgo   string        `json:"encryption_algo"`
	KDFIterations    int           `json:"kdf_iterations"`
}

// KeyManager 密钥管理器
type KeyManager struct {
	config     *KeyManagerConfig
	keys       map[string]*EncryptedKey
	masterKey  []byte
	mu         sync.RWMutex
	rotationCh chan string
	stopCh     chan struct{}
}

// NewKeyManager 创建新的密钥管理器
func NewKeyManager(config *KeyManagerConfig) (*KeyManager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// 设置默认值
	if config.RotationInterval == 0 {
		config.RotationInterval = 24 * time.Hour
	}
	if config.KeyExpiry == 0 {
		config.KeyExpiry = 30 * 24 * time.Hour
	}
	if config.EncryptionAlgo == "" {
		config.EncryptionAlgo = "aes-256-gcm"
	}
	if config.KDFIterations == 0 {
		config.KDFIterations = 100000
	}

	km := &KeyManager{
		config:     config,
		keys:       make(map[string]*EncryptedKey),
		rotationCh: make(chan string, 100),
		stopCh:     make(chan struct{}),
	}

	// 派生主密钥
	if err := km.deriveMasterKey(); err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	// 加载现有密钥
	if err := km.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	// 启动密钥轮换协程
	go km.rotationWorker()

	return km, nil
}

// deriveMasterKey 派生主密钥
func (km *KeyManager) deriveMasterKey() error {
	if km.config.MasterPassword == "" {
		return errors.New("master password is required")
	}

	// 使用 Argon2id 派生主密钥
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// 尝试从文件加载盐值
	saltPath := filepath.Join(km.config.KeyStorePath, "master.salt")
	if data, err := os.ReadFile(saltPath); err == nil {
		salt = data
	} else {
		// 保存新生成的盐值
		if err := os.MkdirAll(km.config.KeyStorePath, 0700); err != nil {
			return fmt.Errorf("failed to create key store directory: %w", err)
		}
		if err := os.WriteFile(saltPath, salt, 0600); err != nil {
			return fmt.Errorf("failed to save salt: %w", err)
		}
	}

	// 使用 Argon2id 派生密钥
	km.masterKey = argon2.IDKey(
		[]byte(km.config.MasterPassword),
		salt,
		1,      // time
		64*1024, // memory (64MB)
		4,      // threads
		32,     // key length
	)

	return nil
}

// GenerateKey 生成新密钥
func (km *KeyManager) GenerateKey(keyType KeyType, keyID string) ([]byte, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	// 检查密钥是否已存在
	if _, exists := km.keys[keyID]; exists {
		return nil, fmt.Errorf("key with ID %s already exists", keyID)
	}

	// 生成密钥
	var keyData []byte
	var err error

	switch keyType {
	case KeyTypeAES256:
		keyData = make([]byte, 32) // 256 bits
	case KeyTypeChaCha20:
		keyData = make([]byte, 32) // 256 bits
	case KeyTypeHMAC:
		keyData = make([]byte, 64) // 512 bits
	case KeyTypePreShared:
		keyData = make([]byte, 32) // 256 bits
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	if _, err = rand.Read(keyData); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// 创建密钥元数据
	now := time.Now()
	metadata := KeyMetadata{
		ID:          keyID,
		Type:        keyType,
		CreatedAt:   now,
		ExpiresAt:   now.Add(km.config.KeyExpiry),
		RotationDue: now.Add(km.config.RotationInterval),
		Version:     1,
		Active:      true,
		UsageCount:  0,
	}

	// 加密并存储密钥
	if err := km.encryptAndStoreKey(keyID, keyData, metadata); err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	return keyData, nil
}

// GetKey 获取密钥
func (km *KeyManager) GetKey(keyID string) ([]byte, error) {
	km.mu.RLock()
	encryptedKey, exists := km.keys[keyID]
	km.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}

	if !encryptedKey.Metadata.Active {
		return nil, fmt.Errorf("key with ID %s is inactive", keyID)
	}

	// 检查密钥是否过期
	if time.Now().After(encryptedKey.Metadata.ExpiresAt) {
		return nil, fmt.Errorf("key with ID %s has expired", keyID)
	}

	// 解密密钥
	keyData, err := km.decryptKey(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// 更新使用计数
	km.mu.Lock()
	encryptedKey.Metadata.UsageCount++
	km.mu.Unlock()

	// 检查是否需要轮换
	if time.Now().After(encryptedKey.Metadata.RotationDue) {
		select {
		case km.rotationCh <- keyID:
		default:
			// 轮换队列已满，跳过
		}
	}

	return keyData, nil
}

// RotateKey 轮换密钥
func (km *KeyManager) RotateKey(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	oldKey, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	// 生成新密钥
	newKeyData := make([]byte, len(km.getKeySize(oldKey.Metadata.Type)))
	if _, err := rand.Read(newKeyData); err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	// 创建新的元数据
	now := time.Now()
	newMetadata := KeyMetadata{
		ID:          keyID,
		Type:        oldKey.Metadata.Type,
		CreatedAt:   now,
		ExpiresAt:   now.Add(km.config.KeyExpiry),
		RotationDue: now.Add(km.config.RotationInterval),
		Version:     oldKey.Metadata.Version + 1,
		Active:      true,
		UsageCount:  0,
	}

	// 备份旧密钥
	if km.config.BackupEnabled {
		if err := km.backupKey(keyID, oldKey); err != nil {
			return fmt.Errorf("failed to backup old key: %w", err)
		}
	}

	// 停用旧密钥
	oldKey.Metadata.Active = false

	// 存储新密钥
	if err := km.encryptAndStoreKey(keyID, newKeyData, newMetadata); err != nil {
		return fmt.Errorf("failed to store new key: %w", err)
	}

	return nil
}

// encryptAndStoreKey 加密并存储密钥
func (km *KeyManager) encryptAndStoreKey(keyID string, keyData []byte, metadata KeyMetadata) error {
	// 生成随机 nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 创建 AES-GCM 加密器
	block, err := aes.NewCipher(km.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// 加密密钥数据
	ciphertext := gcm.Seal(nil, nonce, keyData, nil)

	// 创建加密密钥结构
	encryptedKey := &EncryptedKey{
		Metadata:   metadata,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Salt:       "", // 盐值已在主密钥派生时使用
	}

	// 存储到内存
	km.keys[keyID] = encryptedKey

	// 持久化到磁盘
	return km.saveKeyToDisk(keyID, encryptedKey)
}

// decryptKey 解密密钥
func (km *KeyManager) decryptKey(encryptedKey *EncryptedKey) ([]byte, error) {
	// 解码 base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedKey.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encryptedKey.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// 创建 AES-GCM 解密器
	block, err := aes.NewCipher(km.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 解密密钥数据
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return plaintext, nil
}

// getKeySize 获取密钥大小
func (km *KeyManager) getKeySize(keyType KeyType) []byte {
	switch keyType {
	case KeyTypeAES256, KeyTypeChaCha20, KeyTypePreShared:
		return make([]byte, 32)
	case KeyTypeHMAC:
		return make([]byte, 64)
	default:
		return make([]byte, 32)
	}
}

// loadKeys 从磁盘加载密钥
func (km *KeyManager) loadKeys() error {
	if _, err := os.Stat(km.config.KeyStorePath); os.IsNotExist(err) {
		return nil // 密钥存储目录不存在，跳过加载
	}

	return filepath.WalkDir(km.config.KeyStorePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".key" {
			return nil
		}

		// 读取密钥文件
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read key file %s: %w", path, err)
		}

		// 解析加密密钥
		var encryptedKey EncryptedKey
		if err := json.Unmarshal(data, &encryptedKey); err != nil {
			return fmt.Errorf("failed to unmarshal key file %s: %w", path, err)
		}

		// 存储到内存
		km.keys[encryptedKey.Metadata.ID] = &encryptedKey

		return nil
	})
}

// saveKeyToDisk 保存密钥到磁盘
func (km *KeyManager) saveKeyToDisk(keyID string, encryptedKey *EncryptedKey) error {
	if err := os.MkdirAll(km.config.KeyStorePath, 0700); err != nil {
		return fmt.Errorf("failed to create key store directory: %w", err)
	}

	// 序列化密钥
	data, err := json.MarshalIndent(encryptedKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// 写入文件
	filePath := filepath.Join(km.config.KeyStorePath, keyID+".key")
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// backupKey 备份密钥
func (km *KeyManager) backupKey(keyID string, encryptedKey *EncryptedKey) error {
	if !km.config.BackupEnabled || km.config.BackupPath == "" {
		return nil
	}

	backupDir := filepath.Join(km.config.BackupPath, time.Now().Format("2006-01-02"))
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// 序列化密钥
	data, err := json.MarshalIndent(encryptedKey, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup key: %w", err)
	}

	// 写入备份文件
	backupFile := filepath.Join(backupDir, fmt.Sprintf("%s_v%d.key.bak", keyID, encryptedKey.Metadata.Version))
	if err := os.WriteFile(backupFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// rotationWorker 密钥轮换工作协程
func (km *KeyManager) rotationWorker() {
	ticker := time.NewTicker(time.Hour) // 每小时检查一次
	defer ticker.Stop()

	for {
		select {
		case keyID := <-km.rotationCh:
			if err := km.RotateKey(keyID); err != nil {
				// 记录错误但不停止工作协程
				fmt.Printf("Failed to rotate key %s: %v\n", keyID, err)
			}
		case <-ticker.C:
			// 定期检查需要轮换的密钥
			km.checkRotationDue()
		case <-km.stopCh:
			return
		}
	}
}

// checkRotationDue 检查需要轮换的密钥
func (km *KeyManager) checkRotationDue() {
	km.mu.RLock()
	now := time.Now()
	for keyID, encryptedKey := range km.keys {
		if encryptedKey.Metadata.Active && now.After(encryptedKey.Metadata.RotationDue) {
			select {
			case km.rotationCh <- keyID:
			default:
				// 轮换队列已满，跳过
			}
		}
	}
	km.mu.RUnlock()
}

// ListKeys 列出所有密钥
func (km *KeyManager) ListKeys() []KeyMetadata {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var keys []KeyMetadata
	for _, encryptedKey := range km.keys {
		keys = append(keys, encryptedKey.Metadata)
	}

	return keys
}

// DeleteKey 删除密钥
func (km *KeyManager) DeleteKey(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	encryptedKey, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	// 备份密钥（如果启用）
	if km.config.BackupEnabled {
		if err := km.backupKey(keyID, encryptedKey); err != nil {
			return fmt.Errorf("failed to backup key before deletion: %w", err)
		}
	}

	// 从内存中删除
	delete(km.keys, keyID)

	// 从磁盘删除
	filePath := filepath.Join(km.config.KeyStorePath, keyID+".key")
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	return nil
}

// Close 关闭密钥管理器
func (km *KeyManager) Close() error {
	close(km.stopCh)
	return nil
}

// DeriveKeyFromPassword 从密码派生密钥
func DeriveKeyFromPassword(password, salt []byte, iterations int) []byte {
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

// GenerateSecureRandom 生成安全随机数
func GenerateSecureRandom(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("failed to generate secure random: %w", err)
	}
	return data, nil
}