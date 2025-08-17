package security

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuditLevel 审计级别
type AuditLevel string

const (
	AuditLevelInfo     AuditLevel = "info"
	AuditLevelWarning  AuditLevel = "warning"
	AuditLevelError    AuditLevel = "error"
	AuditLevelCritical AuditLevel = "critical"
)

// AuditCategory 审计类别
type AuditCategory string

const (
	AuditCategoryAuth       AuditCategory = "authentication"
	AuditCategoryAccess     AuditCategory = "access_control"
	AuditCategoryConnection AuditCategory = "connection"
	AuditCategoryProxy      AuditCategory = "proxy"
	AuditCategorySecurity   AuditCategory = "security"
	AuditCategorySystem     AuditCategory = "system"
	AuditCategoryConfig     AuditCategory = "configuration"
	AuditCategoryData       AuditCategory = "data"
)

// DetailedAuditEvent 详细审计事件
type DetailedAuditEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Level       AuditLevel             `json:"level"`
	Category    AuditCategory          `json:"category"`
	EventType   string                 `json:"event_type"`
	UserID      string                 `json:"user_id,omitempty"`
	Username    string                 `json:"username,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Result      string                 `json:"result"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	CorrelationID string               `json:"correlation_id,omitempty"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
}

// AuditLoggerConfig 审计日志配置
type AuditLoggerConfig struct {
	LogPath          string        `json:"log_path"`
	MaxFileSize      int64         `json:"max_file_size"`      // 字节
	MaxFiles         int           `json:"max_files"`          // 保留的日志文件数量
	CompressionLevel int           `json:"compression_level"`  // gzip压缩级别
	FlushInterval    time.Duration `json:"flush_interval"`     // 刷新间隔
	BufferSize       int           `json:"buffer_size"`        // 缓冲区大小
	AsyncLogging     bool          `json:"async_logging"`      // 异步日志记录
	EnableRotation   bool          `json:"enable_rotation"`    // 启用日志轮转
	EnableCompression bool         `json:"enable_compression"` // 启用压缩
	MinLevel         AuditLevel    `json:"min_level"`          // 最小记录级别
	IncludeStackTrace bool         `json:"include_stack_trace"`// 包含堆栈跟踪
}

// EnhancedAuditLogger 增强审计日志记录器
type EnhancedAuditLogger struct {
	config       *AuditLoggerConfig
	currentFile  *os.File
	writer       *bufio.Writer
	gzipWriter   *gzip.Writer
	buffer       chan DetailedAuditEvent
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
	currentSize  int64
	fileIndex    int
	statistics   *AuditStatistics
}

// AuditStatistics 审计统计信息
type AuditStatistics struct {
	TotalEvents      int64                    `json:"total_events"`
	EventsByLevel    map[AuditLevel]int64     `json:"events_by_level"`
	EventsByCategory map[AuditCategory]int64  `json:"events_by_category"`
	EventsByType     map[string]int64         `json:"events_by_type"`
	LastEvent        time.Time                `json:"last_event"`
	StartTime        time.Time                `json:"start_time"`
	mu               sync.RWMutex
}

// AuditQuery 审计查询条件
type AuditQuery struct {
	StartTime     *time.Time              `json:"start_time,omitempty"`
	EndTime       *time.Time              `json:"end_time,omitempty"`
	Level         *AuditLevel             `json:"level,omitempty"`
	Category      *AuditCategory          `json:"category,omitempty"`
	EventType     string                  `json:"event_type,omitempty"`
	UserID        string                  `json:"user_id,omitempty"`
	IPAddress     string                  `json:"ip_address,omitempty"`
	Resource      string                  `json:"resource,omitempty"`
	Action        string                  `json:"action,omitempty"`
	Result        string                  `json:"result,omitempty"`
	Limit         int                     `json:"limit,omitempty"`
	Offset        int                     `json:"offset,omitempty"`
	SortBy        string                  `json:"sort_by,omitempty"`
	SortOrder     string                  `json:"sort_order,omitempty"` // asc, desc
}

// NewEnhancedAuditLogger 创建增强审计日志记录器
func NewEnhancedAuditLogger(config *AuditLoggerConfig) (*EnhancedAuditLogger, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// 设置默认值
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 10
	}
	if config.CompressionLevel == 0 {
		config.CompressionLevel = gzip.DefaultCompression
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.MinLevel == "" {
		config.MinLevel = AuditLevelInfo
	}

	logger := &EnhancedAuditLogger{
		config:     config,
		buffer:     make(chan DetailedAuditEvent, config.BufferSize),
		stopCh:     make(chan struct{}),
		statistics: &AuditStatistics{
			EventsByLevel:    make(map[AuditLevel]int64),
			EventsByCategory: make(map[AuditCategory]int64),
			EventsByType:     make(map[string]int64),
			StartTime:        time.Now(),
		},
	}

	// 创建日志目录
	logDir := filepath.Dir(config.LogPath)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 打开日志文件
	if err := logger.openLogFile(); err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// 启动异步日志记录协程
	if config.AsyncLogging {
		logger.wg.Add(1)
		go logger.logWorker()
	}

	// 启动定期刷新协程
	logger.wg.Add(1)
	go logger.flushWorker()

	return logger, nil
}

// LogEvent 记录审计事件
func (al *EnhancedAuditLogger) LogEvent(event DetailedAuditEvent) {
	// 检查日志级别
	if !al.shouldLog(event.Level) {
		return
	}

	// 设置事件ID和时间戳
	if event.ID == "" {
		event.ID = al.generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// 更新统计信息
	al.updateStatistics(event)

	if al.config.AsyncLogging {
		// 异步记录
		select {
		case al.buffer <- event:
		default:
			// 缓冲区满，直接写入
			al.writeEvent(event)
		}
	} else {
		// 同步记录
		al.writeEvent(event)
	}
}

// LogAuth 记录认证事件
func (al *EnhancedAuditLogger) LogAuth(level AuditLevel, eventType, userID, username, ipAddress, result, message string, details map[string]interface{}) {
	event := DetailedAuditEvent{
		Level:     level,
		Category:  AuditCategoryAuth,
		EventType: eventType,
		UserID:    userID,
		Username:  username,
		IPAddress: ipAddress,
		Resource:  "authentication",
		Action:    eventType,
		Result:    result,
		Message:   message,
		Details:   details,
	}
	al.LogEvent(event)
}

// LogAccess 记录访问控制事件
func (al *EnhancedAuditLogger) LogAccess(level AuditLevel, userID, resource, action, result, message string, details map[string]interface{}) {
	event := DetailedAuditEvent{
		Level:     level,
		Category:  AuditCategoryAccess,
		EventType: "access_check",
		UserID:    userID,
		Resource:  resource,
		Action:    action,
		Result:    result,
		Message:   message,
		Details:   details,
	}
	al.LogEvent(event)
}

// LogConnection 记录连接事件
func (al *EnhancedAuditLogger) LogConnection(level AuditLevel, eventType, userID, ipAddress, result, message string, duration time.Duration, details map[string]interface{}) {
	event := DetailedAuditEvent{
		Level:     level,
		Category:  AuditCategoryConnection,
		EventType: eventType,
		UserID:    userID,
		IPAddress: ipAddress,
		Resource:  "connection",
		Action:    eventType,
		Result:    result,
		Message:   message,
		Duration:  duration,
		Details:   details,
	}
	al.LogEvent(event)
}

// LogSecurity 记录安全事件
func (al *EnhancedAuditLogger) LogSecurity(level AuditLevel, eventType, userID, ipAddress, resource, action, result, message string, details map[string]interface{}) {
	event := DetailedAuditEvent{
		Level:     level,
		Category:  AuditCategorySecurity,
		EventType: eventType,
		UserID:    userID,
		IPAddress: ipAddress,
		Resource:  resource,
		Action:    action,
		Result:    result,
		Message:   message,
		Details:   details,
	}
	al.LogEvent(event)
}

// QueryEvents 查询审计事件
func (al *EnhancedAuditLogger) QueryEvents(query AuditQuery) ([]DetailedAuditEvent, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()

	var events []DetailedAuditEvent

	// 获取所有日志文件
	logFiles, err := al.getLogFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get log files: %w", err)
	}

	// 读取和过滤事件
	for _, logFile := range logFiles {
		fileEvents, err := al.readEventsFromFile(logFile, query)
		if err != nil {
			continue // 跳过错误的文件
		}
		events = append(events, fileEvents...)
	}

	// 排序
	al.sortEvents(events, query.SortBy, query.SortOrder)

	// 分页
	if query.Offset > 0 || query.Limit > 0 {
		events = al.paginateEvents(events, query.Offset, query.Limit)
	}

	return events, nil
}

// GetStatistics 获取审计统计信息
func (al *EnhancedAuditLogger) GetStatistics() *AuditStatistics {
	al.statistics.mu.RLock()
	defer al.statistics.mu.RUnlock()

	// 创建副本以避免并发访问问题
	stats := &AuditStatistics{
		TotalEvents:      al.statistics.TotalEvents,
		EventsByLevel:    make(map[AuditLevel]int64),
		EventsByCategory: make(map[AuditCategory]int64),
		EventsByType:     make(map[string]int64),
		LastEvent:        al.statistics.LastEvent,
		StartTime:        al.statistics.StartTime,
	}

	for k, v := range al.statistics.EventsByLevel {
		stats.EventsByLevel[k] = v
	}
	for k, v := range al.statistics.EventsByCategory {
		stats.EventsByCategory[k] = v
	}
	for k, v := range al.statistics.EventsByType {
		stats.EventsByType[k] = v
	}

	return stats
}

// RotateLog 手动轮转日志
func (al *EnhancedAuditLogger) RotateLog() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	return al.rotateLogFile()
}

// Close 关闭审计日志记录器
func (al *EnhancedAuditLogger) Close() error {
	// 停止工作协程
	close(al.stopCh)
	al.wg.Wait()

	al.mu.Lock()
	defer al.mu.Unlock()

	// 刷新缓冲区
	if al.writer != nil {
		al.writer.Flush()
	}

	// 关闭gzip写入器
	if al.gzipWriter != nil {
		al.gzipWriter.Close()
	}

	// 关闭文件
	if al.currentFile != nil {
		al.currentFile.Close()
	}

	return nil
}

// shouldLog 检查是否应该记录该级别的日志
func (al *EnhancedAuditLogger) shouldLog(level AuditLevel) bool {
	levelOrder := map[AuditLevel]int{
		AuditLevelInfo:     0,
		AuditLevelWarning:  1,
		AuditLevelError:    2,
		AuditLevelCritical: 3,
	}

	return levelOrder[level] >= levelOrder[al.config.MinLevel]
}

// generateEventID 生成事件ID
func (al *EnhancedAuditLogger) generateEventID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), al.statistics.TotalEvents)
}

// updateStatistics 更新统计信息
func (al *EnhancedAuditLogger) updateStatistics(event DetailedAuditEvent) {
	al.statistics.mu.Lock()
	defer al.statistics.mu.Unlock()

	al.statistics.TotalEvents++
	al.statistics.EventsByLevel[event.Level]++
	al.statistics.EventsByCategory[event.Category]++
	al.statistics.EventsByType[event.EventType]++
	al.statistics.LastEvent = event.Timestamp
}

// logWorker 异步日志记录工作协程
func (al *EnhancedAuditLogger) logWorker() {
	defer al.wg.Done()

	for {
		select {
		case event := <-al.buffer:
			al.writeEvent(event)
		case <-al.stopCh:
			// 处理剩余的事件
			for {
				select {
				case event := <-al.buffer:
					al.writeEvent(event)
				default:
					return
				}
			}
		}
	}
}

// flushWorker 定期刷新工作协程
func (al *EnhancedAuditLogger) flushWorker() {
	defer al.wg.Done()

	ticker := time.NewTicker(al.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			al.flush()
		case <-al.stopCh:
			al.flush()
			return
		}
	}
}

// writeEvent 写入事件到日志文件
func (al *EnhancedAuditLogger) writeEvent(event DetailedAuditEvent) {
	al.mu.Lock()
	defer al.mu.Unlock()

	// 序列化事件
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	// 添加换行符
	data = append(data, '\n')

	// 检查是否需要轮转日志
	if al.config.EnableRotation && al.currentSize+int64(len(data)) > al.config.MaxFileSize {
		if err := al.rotateLogFile(); err != nil {
			return
		}
	}

	// 写入数据
	if al.config.EnableCompression && al.gzipWriter != nil {
		al.gzipWriter.Write(data)
	} else if al.writer != nil {
		al.writer.Write(data)
	}

	al.currentSize += int64(len(data))
}

// flush 刷新缓冲区
func (al *EnhancedAuditLogger) flush() {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.gzipWriter != nil {
		al.gzipWriter.Flush()
	}
	if al.writer != nil {
		al.writer.Flush()
	}
	if al.currentFile != nil {
		al.currentFile.Sync()
	}
}

// openLogFile 打开日志文件
func (al *EnhancedAuditLogger) openLogFile() error {
	// 生成文件名
	fileName := al.generateLogFileName()

	// 打开文件
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}

	// 获取文件大小
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	al.currentFile = file
	al.currentSize = stat.Size()

	// 创建写入器
	if al.config.EnableCompression {
		al.gzipWriter, err = gzip.NewWriterLevel(file, al.config.CompressionLevel)
		if err != nil {
			file.Close()
			return err
		}
		al.writer = bufio.NewWriter(al.gzipWriter)
	} else {
		al.writer = bufio.NewWriter(file)
	}

	return nil
}

// rotateLogFile 轮转日志文件
func (al *EnhancedAuditLogger) rotateLogFile() error {
	// 刷新并关闭当前文件
	if al.writer != nil {
		al.writer.Flush()
	}
	if al.gzipWriter != nil {
		al.gzipWriter.Close()
		al.gzipWriter = nil
	}
	if al.currentFile != nil {
		al.currentFile.Close()
		al.currentFile = nil
	}

	// 重命名当前文件
	currentFileName := al.generateLogFileName()
	rotatedFileName := al.generateRotatedFileName()

	if _, err := os.Stat(currentFileName); err == nil {
		if err := os.Rename(currentFileName, rotatedFileName); err != nil {
			return err
		}
	}

	// 清理旧文件
	if err := al.cleanupOldFiles(); err != nil {
		return err
	}

	// 打开新文件
	al.fileIndex++
	return al.openLogFile()
}

// generateLogFileName 生成日志文件名
func (al *EnhancedAuditLogger) generateLogFileName() string {
	if al.config.EnableCompression {
		return al.config.LogPath + ".gz"
	}
	return al.config.LogPath
}

// generateRotatedFileName 生成轮转后的文件名
func (al *EnhancedAuditLogger) generateRotatedFileName() string {
	timestamp := time.Now().Format("20060102-150405")
	baseName := al.config.LogPath
	if al.config.EnableCompression {
		return fmt.Sprintf("%s.%s.%d.gz", baseName, timestamp, al.fileIndex)
	}
	return fmt.Sprintf("%s.%s.%d", baseName, timestamp, al.fileIndex)
}

// cleanupOldFiles 清理旧的日志文件
func (al *EnhancedAuditLogger) cleanupOldFiles() error {
	logDir := filepath.Dir(al.config.LogPath)
	baseName := filepath.Base(al.config.LogPath)

	// 获取所有相关的日志文件
	files, err := filepath.Glob(filepath.Join(logDir, baseName+".*"))
	if err != nil {
		return err
	}

	// 按修改时间排序
	sort.Slice(files, func(i, j int) bool {
		stat1, err1 := os.Stat(files[i])
		stat2, err2 := os.Stat(files[j])
		if err1 != nil || err2 != nil {
			return false
		}
		return stat1.ModTime().After(stat2.ModTime())
	})

	// 删除超出保留数量的文件
	if len(files) > al.config.MaxFiles {
		for _, file := range files[al.config.MaxFiles:] {
			os.Remove(file)
		}
	}

	return nil
}

// getLogFiles 获取所有日志文件
func (al *EnhancedAuditLogger) getLogFiles() ([]string, error) {
	logDir := filepath.Dir(al.config.LogPath)
	baseName := filepath.Base(al.config.LogPath)

	// 获取所有相关的日志文件
	files, err := filepath.Glob(filepath.Join(logDir, baseName+"*"))
	if err != nil {
		return nil, err
	}

	// 按修改时间排序（最新的在前）
	sort.Slice(files, func(i, j int) bool {
		stat1, err1 := os.Stat(files[i])
		stat2, err2 := os.Stat(files[j])
		if err1 != nil || err2 != nil {
			return false
		}
		return stat1.ModTime().After(stat2.ModTime())
	})

	return files, nil
}

// readEventsFromFile 从文件读取事件
func (al *EnhancedAuditLogger) readEventsFromFile(filePath string, query AuditQuery) ([]DetailedAuditEvent, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reader io.Reader = file

	// 检查是否是压缩文件
	if strings.HasSuffix(filePath, ".gz") {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	var events []DetailedAuditEvent
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		var event DetailedAuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue // 跳过无效的行
		}

		// 应用过滤条件
		if al.matchesQuery(event, query) {
			events = append(events, event)
		}
	}

	return events, scanner.Err()
}

// matchesQuery 检查事件是否匹配查询条件
func (al *EnhancedAuditLogger) matchesQuery(event DetailedAuditEvent, query AuditQuery) bool {
	// 时间范围过滤
	if query.StartTime != nil && event.Timestamp.Before(*query.StartTime) {
		return false
	}
	if query.EndTime != nil && event.Timestamp.After(*query.EndTime) {
		return false
	}

	// 级别过滤
	if query.Level != nil && event.Level != *query.Level {
		return false
	}

	// 类别过滤
	if query.Category != nil && event.Category != *query.Category {
		return false
	}

	// 事件类型过滤
	if query.EventType != "" && event.EventType != query.EventType {
		return false
	}

	// 用户ID过滤
	if query.UserID != "" && event.UserID != query.UserID {
		return false
	}

	// IP地址过滤
	if query.IPAddress != "" && event.IPAddress != query.IPAddress {
		return false
	}

	// 资源过滤
	if query.Resource != "" && !strings.Contains(event.Resource, query.Resource) {
		return false
	}

	// 动作过滤
	if query.Action != "" && !strings.Contains(event.Action, query.Action) {
		return false
	}

	// 结果过滤
	if query.Result != "" && event.Result != query.Result {
		return false
	}

	return true
}

// sortEvents 排序事件
func (al *EnhancedAuditLogger) sortEvents(events []DetailedAuditEvent, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "timestamp"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	sort.Slice(events, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "timestamp":
			less = events[i].Timestamp.Before(events[j].Timestamp)
		case "level":
			levelOrder := map[AuditLevel]int{
				AuditLevelInfo:     0,
				AuditLevelWarning:  1,
				AuditLevelError:    2,
				AuditLevelCritical: 3,
			}
			less = levelOrder[events[i].Level] < levelOrder[events[j].Level]
		case "category":
			less = events[i].Category < events[j].Category
		case "event_type":
			less = events[i].EventType < events[j].EventType
		case "user_id":
			less = events[i].UserID < events[j].UserID
		default:
			less = events[i].Timestamp.Before(events[j].Timestamp)
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// paginateEvents 分页事件
func (al *EnhancedAuditLogger) paginateEvents(events []DetailedAuditEvent, offset, limit int) []DetailedAuditEvent {
	if offset >= len(events) {
		return []DetailedAuditEvent{}
	}

	end := len(events)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}

	return events[offset:end]
}