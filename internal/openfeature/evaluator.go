package openfeature

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/dovocoder/reflag/internal/models"
)

// SecretResolver is a function that resolves a secret key to its decrypted value.
// If the secret doesn't exist or decryption fails, it returns ("", error).
type SecretResolver func(key string) (string, error)

// ResolutionContext provides evaluation-time metadata.
type ResolutionContext struct {
	TargetingKey string         `json:"targetingKey,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
}

// ResolutionDetail holds the result of flag evaluation.
type ResolutionDetail struct {
	Value      any             `json:"value"`
	Variant    string          `json:"variant"`
	Reason     string          `json:"reason"` // DEFAULT, TARGETING_MATCH, DISABLED, ERROR
	ErrorCode  string          `json:"errorCode,omitempty"`
	ErrorMsg   string          `json:"errorMessage,omitempty"`
	FlagMetadata map[string]any `json:"flagMetadata,omitempty"`
}

// EvaluationError represents an evaluation error.
type EvaluationError struct {
	Code        string `json:"errorCode"`
	Message     string `json:"errorMessage"`
}

func (e *EvaluationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Evaluate resolves a flag against the given evaluation context.
// This implements the OpenFeature evaluation logic.
func Evaluate(flag *models.Flag, envKey string, ctx ResolutionContext) ResolutionDetail {
	// Flag is disabled — return the default variation
	if !flag.Enabled {
		return ResolutionDetail{
			Value:   getVariationValue(flag, flag.DefaultRule),
			Variant: getVariationLabel(flag, flag.DefaultRule.VariationID),
			Reason:  ReasonDisabled,
		}
	}

	// Try targeting rules first (in order)
	for _, rule := range flag.Targeting {
		if matchesAllConditions(rule.Conditions, ctx) {
			return ResolutionDetail{
				Value:   getVariationValueByID(flag, rule.VariationID),
				Variant: getVariationLabelByID(flag, rule.VariationID),
				Reason:  ReasonTargetingMatch,
			}
		}
	}

	// Apply default rule (with percentage rollout if configured)
	if flag.DefaultRule != nil {
		if len(flag.DefaultRule.Percentage) > 0 {
			variationID := percentageBucket(flag.Key, envKey, ctx.TargetingKey, flag.DefaultRule.Percentage)
			return ResolutionDetail{
				Value:   getVariationValueByID(flag, variationID),
				Variant: getVariationLabelByID(flag, variationID),
				Reason:  ReasonSplit,
			}
		}
		return ResolutionDetail{
			Value:   getVariationValueByID(flag, flag.DefaultRule.VariationID),
			Variant: getVariationLabelByID(flag, flag.DefaultRule.VariationID),
			Reason:  ReasonDefault,
		}
	}

	// No default rule — error
	return ResolutionDetail{
		Value:     nil,
		Reason:    ReasonError,
		ErrorCode: "FLAG_NOT_CONFIGURED",
		ErrorMsg:  "flag has no default rule configured",
	}
}

// EvaluateWithSecrets works like Evaluate but resolves any variation values
// that are secret references ({"$secret": "KEY"}) to their decrypted values.
// If resolver is nil, secret references are returned as-is (the JSON object).
func EvaluateWithSecrets(flag *models.Flag, envKey string, ctx ResolutionContext, resolver SecretResolver) ResolutionDetail {
	detail := Evaluate(flag, envKey, ctx)
	if resolver == nil {
		return detail
	}
	// Check if the resolved value is a secret reference
	if detail.Value == nil {
		return detail
	}
	resolvedValue, err := resolveSecretValue(detail.Value, resolver)
	if err != nil {
		detail.Reason = ReasonError
		detail.ErrorCode = "SECRET_RESOLUTION_FAILED"
		detail.ErrorMsg = err.Error()
		return detail
	}
	detail.Value = resolvedValue
	return detail
}

// resolveSecretValue checks if a value is a secret reference and resolves it.
// A secret reference is an object with a "$secret" key: {"$secret": "DATABASE_URL"}.
// Non-secret values are returned as-is.
func resolveSecretValue(val any, resolver SecretResolver) (any, error) {
	m, ok := val.(map[string]any)
	if !ok {
		return val, nil
	}
	secretKey, hasRef := m["$secret"]
	if !hasRef {
		return val, nil // regular object, not a secret ref
	}
	keyStr, ok := secretKey.(string)
	if !ok {
		return nil, fmt.Errorf("$secret value must be a string, got %T", secretKey)
	}
	decrypted, err := resolver(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve secret %q: %w", keyStr, err)
	}
	return decrypted, nil
}

const (
	ReasonTargetingMatch = "TARGETING_MATCH"
	ReasonSplit         = "SPLIT"
	ReasonDisabled      = "DISABLED"
	ReasonDefault       = "DEFAULT"
	ReasonError         = "ERROR"
	ReasonNotFound      = "FLAG_NOT_FOUND"
)

// matchesAllConditions checks if all conditions in a rule match the context.
func matchesAllConditions(conditions []models.Condition, ctx ResolutionContext) bool {
	if len(conditions) == 0 {
		return false // empty conditions never match
	}
	for _, cond := range conditions {
		if !matchesCondition(cond, ctx) {
			return false
		}
	}
	return true
}

// matchesCondition evaluates a single condition against the context.
func matchesCondition(cond models.Condition, ctx ResolutionContext) bool {
	var attrVal any
	if cond.Attribute == "targetingKey" {
		attrVal = ctx.TargetingKey
	} else {
		attrVal = ctx.Attributes[cond.Attribute]
	}

	if attrVal == nil {
		return false
	}

	attrStr := fmt.Sprintf("%v", attrVal)

	switch cond.Operator {
	case "eq", "EQUALS":
		for _, v := range cond.Values {
			if attrStr == v {
				return true
			}
		}
		return false
	case "neq", "NOT_EQUALS":
		for _, v := range cond.Values {
			if attrStr == v {
				return false
			}
		}
		return true
	case "in", "IN":
		for _, v := range cond.Values {
			if attrStr == v {
				return true
			}
		}
		return false
	case "not_in", "NOT_IN":
		for _, v := range cond.Values {
			if attrStr == v {
				return false
			}
		}
		return true
	case "starts_with", "STARTS_WITH":
		for _, v := range cond.Values {
			if strings.HasPrefix(attrStr, v) {
				return true
			}
		}
		return false
	case "ends_with", "ENDS_WITH":
		for _, v := range cond.Values {
			if strings.HasSuffix(attrStr, v) {
				return true
			}
		}
		return false
	case "contains", "CONTAINS":
		for _, v := range cond.Values {
			if strings.Contains(attrStr, v) {
				return true
			}
		}
		return false
	case "gt", "GREATER_THAN":
		attrNum, ok := toFloat64(attrVal)
		if !ok {
			return false
		}
		for _, v := range cond.Values {
			if num, err := parseFloat(v); err == nil && attrNum > num {
				return true
			}
		}
		return false
	case "gte", "GREATER_THAN_OR_EQUAL":
		attrNum, ok := toFloat64(attrVal)
		if !ok {
			return false
		}
		for _, v := range cond.Values {
			if num, err := parseFloat(v); err == nil && attrNum >= num {
				return true
			}
		}
		return false
	case "lt", "LESS_THAN":
		attrNum, ok := toFloat64(attrVal)
		if !ok {
			return false
		}
		for _, v := range cond.Values {
			if num, err := parseFloat(v); err == nil && attrNum < num {
				return true
			}
		}
		return false
	case "lte", "LESS_THAN_OR_EQUAL":
		attrNum, ok := toFloat64(attrVal)
		if !ok {
			return false
		}
		for _, v := range cond.Values {
			if num, err := parseFloat(v); err == nil && attrNum <= num {
				return true
			}
		}
		return false
	case "true", "TRUE":
		return attrVal == true || attrStr == "true"
	case "false", "FALSE":
		return attrVal == false || attrStr == "false"
	case "empty", "EMPTY":
		return attrStr == ""
	case "not_empty", "NOT_EMPTY":
		return attrStr != ""
	case "regex", "REGEX":
		// Regex matching is not enabled by default for security
		return false
	default:
		return false
	}
}

// percentageBucket determines which variation a key falls into using
// a deterministic hash-based bucketing algorithm (OpenFeature spec compliant).
func percentageBucket(flagKey, envKey, targetingKey string, percentages map[string]int) string {
	// Sort variation IDs for deterministic bucketing
	variationIDs := make([]string, 0, len(percentages))
	for id := range percentages {
		variationIDs = append(variationIDs, id)
	}
	sort.Strings(variationIDs)

	// Compute hash
	hashInput := fmt.Sprintf("%s:%s:%s", flagKey, envKey, targetingKey)
	h := sha256.Sum256([]byte(hashInput))
	// Use first 8 bytes as uint64
	bucket := binary.BigEndian.Uint64(h[:8]) % 100

	// Walk the bucket ranges
	cumulative := 0
	for _, id := range variationIDs {
		cumulative += percentages[id]
		if int(bucket) < cumulative {
			return id
		}
	}

	// Fallback to first variation
	return variationIDs[0]
}

// getVariationValue returns the value for the default rule's variation.
func getVariationValue(flag *models.Flag, rule *models.DefaultRule) any {
	if rule == nil {
		return nil
	}
	return getVariationValueByID(flag, rule.VariationID)
}

// getVariationValueByID finds a variation by ID and returns its value.
func getVariationValueByID(flag *models.Flag, variationID string) any {
	for _, v := range flag.Variations {
		if v.ID == variationID {
			var val any
			if err := json.Unmarshal(v.Value, &val); err != nil {
				return nil
			}
			return val
		}
	}
	return nil
}

// getVariationLabelByID returns the human-readable label for a variation.
func getVariationLabelByID(flag *models.Flag, variationID string) string {
	for _, v := range flag.Variations {
		if v.ID == variationID {
			return v.Label
		}
	}
	return ""
}

func getVariationLabel(flag *models.Flag, variationID string) string {
	return getVariationLabelByID(flag, variationID)
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := parseFloat(n)
		return f, err == nil
	default:
		return 0, false
	}
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%g", &f)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("invalid number")
	}
	return f, nil
}
