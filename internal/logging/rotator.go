package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogRotatorConfig 日志轮转配置
type LogRotatorConfig struct {
	Filename  string        `json:"filename"`   // 日志文件名
	MaxSize   int64         `json:"max_size"`   // 最大文件大小（字节）
	MaxFiles  int           `json:"max_files"`  // 最大文件数量
	MaxAge    time.Duration `json:"max_age"`    // 最大保留时间
	Compress  bool          `json:"compress"`   // 是否压缩
	LocalTime bool          `json:"local_time"` // 使用本地时间
}

// LogRotator 日志轮转器
type LogRotator struct {
	config      *LogRotatorConfig
	file        *os.File
	mu          sync.Mutex
	currentSize int64
}

// NewLogRotator 创建日志轮转器
func NewLogRotator(config *LogRotatorConfig) (*LogRotator, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.Filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	// 设置默认值
	if config.MaxSize == 0 {
		config.MaxSize = 100 * 1024 * 1024 // 100MB
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 10
	}
	if config.MaxAge == 0 {
		config.MaxAge = 30 * 24 * time.Hour // 30天
	}

	rotator := &LogRotator{
		config: config,
	}

	// 打开日志文件
	if err := rotator.openFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return rotator, nil
}

// Write 实现io.Writer接口
func (lr *LogRotator) Write(p []byte) (n int, err error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	// 检查是否需要轮转
	if lr.shouldRotate(len(p)) {
		if err := lr.rotate(); err != nil {
			return 0, fmt.Errorf("failed to rotate log: %w", err)
		}
	}

	// 写入数据
	n, err = lr.file.Write(p)
	if err != nil {
		return n, err
	}

	lr.currentSize += int64(n)
	return n, nil
}

// Close 关闭日志轮转器
func (lr *LogRotator) Close() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	if lr.file != nil {
		return lr.file.Close()
	}
	return nil
}

// Rotate 手动轮转日志
func (lr *LogRotator) Rotate() error {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	return lr.rotate()
}

// shouldRotate 检查是否应该轮转
func (lr *LogRotator) shouldRotate(writeLen int) bool {
	return lr.currentSize+int64(writeLen) > lr.config.MaxSize
}

// rotate 执行日志轮转
func (lr *LogRotator) rotate() error {
	// 关闭当前文件
	if lr.file != nil {
		if err := lr.file.Close(); err != nil {
			return err
		}
		lr.file = nil
	}

	// 生成轮转后的文件名
	rotatedName := lr.generateRotatedName()

	// 重命名当前文件
	if _, err := os.Stat(lr.config.Filename); err == nil {
		if err := os.Rename(lr.config.Filename, rotatedName); err != nil {
			return fmt.Errorf("failed to rename log file: %w", err)
		}

		// 压缩文件
		if lr.config.Compress {
			go lr.compressFile(rotatedName)
		}
	}

	// 清理旧文件
	go lr.cleanup()

	// 打开新文件
	return lr.openFile()
}

// openFile 打开日志文件
func (lr *LogRotator) openFile() error {
	// 创建目录
	dir := filepath.Dir(lr.config.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 打开文件
	file, err := os.OpenFile(lr.config.Filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	// 获取文件大小
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to stat file: %w", err)
	}

	lr.file = file
	lr.currentSize = stat.Size()

	return nil
}

// generateRotatedName 生成轮转后的文件名
func (lr *LogRotator) generateRotatedName() string {
	dir := filepath.Dir(lr.config.Filename)
	base := filepath.Base(lr.config.Filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	// 使用时间戳
	var timestamp string
	if lr.config.LocalTime {
		timestamp = time.Now().Format("2006-01-02T15-04-05")
	} else {
		timestamp = time.Now().UTC().Format("2006-01-02T15-04-05")
	}

	return filepath.Join(dir, fmt.Sprintf("%s.%s%s", name, timestamp, ext))
}

// compressFile 压缩文件
func (lr *LogRotator) compressFile(filename string) {
	// 打开源文件
	src, err := os.Open(filename)
	if err != nil {
		return
	}
	defer src.Close()

	// 创建压缩文件
	gzFilename := filename + ".gz"
	dst, err := os.Create(gzFilename)
	if err != nil {
		return
	}
	defer dst.Close()

	// 创建gzip写入器
	gzWriter := gzip.NewWriter(dst)
	defer gzWriter.Close()

	// 复制数据
	if _, err := io.Copy(gzWriter, src); err != nil {
		return
	}

	// 删除原文件
	os.Remove(filename)
}

// cleanup 清理旧文件
func (lr *LogRotator) cleanup() {
	dir := filepath.Dir(lr.config.Filename)
	base := filepath.Base(lr.config.Filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	// 查找所有相关文件
	pattern := filepath.Join(dir, name+".*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// 过滤出轮转文件
	var rotatedFiles []rotatedFile
	for _, file := range files {
		if file == lr.config.Filename {
			continue // 跳过当前文件
		}

		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		rotatedFiles = append(rotatedFiles, rotatedFile{
			name:    file,
			modTime: stat.ModTime(),
		})
	}

	// 按修改时间排序（最新的在前）
	sort.Slice(rotatedFiles, func(i, j int) bool {
		return rotatedFiles[i].modTime.After(rotatedFiles[j].modTime)
	})

	// 删除超出数量限制的文件
	if len(rotatedFiles) > lr.config.MaxFiles {
		for _, file := range rotatedFiles[lr.config.MaxFiles:] {
			os.Remove(file.name)
		}
		rotatedFiles = rotatedFiles[:lr.config.MaxFiles]
	}

	// 删除超出时间限制的文件
	cutoff := time.Now().Add(-lr.config.MaxAge)
	for _, file := range rotatedFiles {
		if file.modTime.Before(cutoff) {
			os.Remove(file.name)
		}
	}
}

// rotatedFile 轮转文件信息
type rotatedFile struct {
	name    string
	modTime time.Time
}
