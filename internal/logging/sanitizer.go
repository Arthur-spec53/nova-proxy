package logging

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// LogSanitizer 日志敏感信息脱敏器
type LogSanitizer struct {
	rules []*compiledSanitizeRule
}

// compiledSanitizeRule 编译后的脱敏规则
type compiledSanitizeRule struct {
	name        string
	regex       *regexp.Regexp
	replacement string
	fields      map[string]bool // 应用的字段，空表示所有字段
}

// NewLogSanitizer 创建日志脱敏器
func NewLogSanitizer(rules []SanitizeRule) (*LogSanitizer, error) {
	if len(rules) == 0 {
		// 使用默认规则
		rules = getDefaultSanitizeRules()
	}

	compiledRules := make([]*compiledSanitizeRule, 0, len(rules))

	for _, rule := range rules {
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern for rule %s: %w", rule.Name, err)
		}

		fieldsMap := make(map[string]bool)
		for _, field := range rule.Fields {
			fieldsMap[field] = true
		}

		compiledRules = append(compiledRules, &compiledSanitizeRule{
			name:        rule.Name,
			regex:       regex,
			replacement: rule.Replacement,
			fields:      fieldsMap,
		})
	}

	return &LogSanitizer{
		rules: compiledRules,
	}, nil
}

// SanitizeString 脱敏字符串
func (ls *LogSanitizer) SanitizeString(input string) string {
	result := input
	for _, rule := range ls.rules {
		result = rule.regex.ReplaceAllString(result, rule.replacement)
	}
	return result
}

// SanitizeValue 脱敏值
func (ls *LogSanitizer) SanitizeValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case string:
		return ls.SanitizeString(v)
	case []byte:
		return []byte(ls.SanitizeString(string(v)))
	case map[string]interface{}:
		return ls.sanitizeMap(v)
	case map[string]string:
		return ls.sanitizeStringMap(v)
	case []interface{}:
		return ls.sanitizeSlice(v)
	case []string:
		return ls.sanitizeStringSlice(v)
	default:
		// 对于其他类型，尝试转换为字符串进行脱敏
		if str := fmt.Sprintf("%v", v); str != "" {
			sanitized := ls.SanitizeString(str)
			if sanitized != str {
				return sanitized
			}
		}
		return value
	}
}

// SanitizeFields 脱敏字段映射
func (ls *LogSanitizer) SanitizeFields(fields map[string]interface{}) map[string]interface{} {
	if len(fields) == 0 {
		return fields
	}

	sanitized := make(map[string]interface{}, len(fields))
	for key, value := range fields {
		sanitized[key] = ls.sanitizeFieldValue(key, value)
	}
	return sanitized
}

// SanitizeJSON 脱敏JSON字符串
func (ls *LogSanitizer) SanitizeJSON(jsonStr string) string {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		// 如果不是有效的JSON，直接脱敏字符串
		return ls.SanitizeString(jsonStr)
	}

	sanitized := ls.SanitizeValue(data)
	if sanitizedBytes, err := json.Marshal(sanitized); err == nil {
		return string(sanitizedBytes)
	}

	// 如果序列化失败，返回原始脱敏字符串
	return ls.SanitizeString(jsonStr)
}

// sanitizeFieldValue 脱敏字段值（考虑字段名）
func (ls *LogSanitizer) sanitizeFieldValue(fieldName string, value interface{}) interface{} {
	if value == nil {
		return nil
	}

	// 检查是否有针对特定字段的规则
	for _, rule := range ls.rules {
		if len(rule.fields) > 0 && !rule.fields[fieldName] {
			continue // 规则不适用于此字段
		}

		switch v := value.(type) {
		case string:
			if sanitized := rule.regex.ReplaceAllString(v, rule.replacement); sanitized != v {
				return sanitized
			}
		case []byte:
			str := string(v)
			if sanitized := rule.regex.ReplaceAllString(str, rule.replacement); sanitized != str {
				return []byte(sanitized)
			}
		}
	}

	// 递归处理复合类型
	return ls.SanitizeValue(value)
}

// sanitizeMap 脱敏映射
func (ls *LogSanitizer) sanitizeMap(m map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{}, len(m))
	for key, value := range m {
		sanitized[key] = ls.sanitizeFieldValue(key, value)
	}
	return sanitized
}

// sanitizeStringMap 脱敏字符串映射
func (ls *LogSanitizer) sanitizeStringMap(m map[string]string) map[string]string {
	sanitized := make(map[string]string, len(m))
	for key, value := range m {
		if sanitizedValue, ok := ls.sanitizeFieldValue(key, value).(string); ok {
			sanitized[key] = sanitizedValue
		} else {
			sanitized[key] = value
		}
	}
	return sanitized
}

// sanitizeSlice 脱敏切片
func (ls *LogSanitizer) sanitizeSlice(slice []interface{}) []interface{} {
	sanitized := make([]interface{}, len(slice))
	for i, value := range slice {
		sanitized[i] = ls.SanitizeValue(value)
	}
	return sanitized
}

// sanitizeStringSlice 脱敏字符串切片
func (ls *LogSanitizer) sanitizeStringSlice(slice []string) []string {
	sanitized := make([]string, len(slice))
	for i, value := range slice {
		if sanitizedValue, ok := ls.SanitizeValue(value).(string); ok {
			sanitized[i] = sanitizedValue
		} else {
			sanitized[i] = value
		}
	}
	return sanitized
}

// getDefaultSanitizeRules 获取默认脱敏规则
func getDefaultSanitizeRules() []SanitizeRule {
	return []SanitizeRule{
		{
			Name:        "password",
			Pattern:     `(?i)(password|pwd|passwd|secret|key|token)\s*[:=]\s*["']?([^\s"',}\]]+)["']?`,
			Replacement: `$1:"***REDACTED***"`,
		},
		{
			Name:        "email",
			Pattern:     `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			Replacement: "***EMAIL***",
		},
		{
			Name:        "phone",
			Pattern:     `\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b`,
			Replacement: "***PHONE***",
		},
		{
			Name:        "credit_card",
			Pattern:     `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`,
			Replacement: "***CARD***",
		},
		{
			Name:        "ssn",
			Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			Replacement: "***SSN***",
		},
		{
			Name:        "ip_address",
			Pattern:     `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			Replacement: "***IP***",
			Fields:      []string{"client_ip", "remote_addr", "x_forwarded_for"},
		},
		{
			Name:        "jwt_token",
			Pattern:     `\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b`,
			Replacement: "***JWT***",
		},
		{
			Name:        "api_key",
			Pattern:     `(?i)(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?`,
			Replacement: `$1:"***API_KEY***"`,
		},
		{
			Name:        "authorization_header",
			Pattern:     `(?i)(authorization|bearer)\s*:\s*["']?([A-Za-z0-9_.-]+)["']?`,
			Replacement: `$1:"***AUTH***"`,
		},
		{
			Name:        "database_url",
			Pattern:     `(?i)(mongodb|mysql|postgres|redis)://[^\s@]+:[^\s@]+@[^\s/]+`,
			Replacement: "***DB_URL***",
		},
	}
}

// AddRule 添加脱敏规则
func (ls *LogSanitizer) AddRule(rule SanitizeRule) error {
	regex, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern for rule %s: %w", rule.Name, err)
	}

	fieldsMap := make(map[string]bool)
	for _, field := range rule.Fields {
		fieldsMap[field] = true
	}

	ls.rules = append(ls.rules, &compiledSanitizeRule{
		name:        rule.Name,
		regex:       regex,
		replacement: rule.Replacement,
		fields:      fieldsMap,
	})

	return nil
}

// RemoveRule 移除脱敏规则
func (ls *LogSanitizer) RemoveRule(name string) {
	for i, rule := range ls.rules {
		if rule.name == name {
			ls.rules = append(ls.rules[:i], ls.rules[i+1:]...)
			return
		}
	}
}

// GetRules 获取所有规则名称
func (ls *LogSanitizer) GetRules() []string {
	rules := make([]string, len(ls.rules))
	for i, rule := range ls.rules {
		rules[i] = rule.name
	}
	return rules
}

// TestRule 测试规则
func (ls *LogSanitizer) TestRule(ruleName, input string) (string, bool) {
	for _, rule := range ls.rules {
		if rule.name == ruleName {
			result := rule.regex.ReplaceAllString(input, rule.replacement)
			return result, result != input
		}
	}
	return input, false
}

// Clone 克隆脱敏器
func (ls *LogSanitizer) Clone() *LogSanitizer {
	clonedRules := make([]*compiledSanitizeRule, len(ls.rules))
	copy(clonedRules, ls.rules)

	return &LogSanitizer{
		rules: clonedRules,
	}
}

// IsEmpty 检查是否为空
func (ls *LogSanitizer) IsEmpty() bool {
	return len(ls.rules) == 0
}

// Stats 获取统计信息
func (ls *LogSanitizer) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_rules": len(ls.rules),
		"rule_names":  ls.GetRules(),
	}
}
