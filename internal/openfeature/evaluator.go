package openfeature

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/dovocoder/reflag/internal/models"
)

// --- OpenFeature spec constants ---

// Reason codes per OpenFeature specification section 2.5.1
const (
	ReasonTargetingMatch = "TARGETING_MATCH"
	ReasonSplit          = "SPLIT"
	ReasonDisabled       = "DISABLED"
	ReasonDefault        = "DEFAULT"
	ReasonStatic         = "STATIC"
	ReasonUnknown        = "UNKNOWN"
	ReasonError          = "ERROR"
)

// Error codes per OpenFeature specification section 2.5.5
const (
	ErrProviderNotReady  = "PROVIDER_NOT_READY"
	ErrProviderFatal     = "PROVIDER_FATAL"
	ErrFlagNotFound      = "FLAG_NOT_FOUND"
	ErrParseError        = "PARSE_ERROR"
	ErrTypeMismatch      = "TYPE_MISMATCH"
	ErrInvalidContext    = "INVALID_CONTEXT"
	ErrGeneral           = "GENERAL"
	ErrSecretNotFound    = "SECRET_NOT_FOUND"
	ErrSecretResolution  = "SECRET_RESOLUTION_FAILED"
)

// FlagMetadata keys
const (
	MetaFlagKey      = "flagKey"
	MetaFlagVersion  = "version"
	MetaEnvironment  = "environment"
)

// SecretResolver resolves a secret key to its decrypted value.
type SecretResolver func(key string) (string, error)

// EvaluationContext provides evaluation-time metadata per OpenFeature spec section 2.2.
type EvaluationContext struct {
	TargetingKey string         `json:"targetingKey,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
}

// ResolutionDetail holds the result of flag evaluation per OpenFeature spec section 2.5.
type ResolutionDetail struct {
	Value        any            `json:"value"`
	Variant      string         `json:"variant"`
	Reason       string         `json:"reason"`
	ErrorCode    string         `json:"errorCode,omitempty"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
	FlagMetadata map[string]any `json:"flagMetadata,omitempty"`
}

// EvaluationRequest is the standard request for flag evaluation.
type EvaluationRequest struct {
	FlagKey      string             `json:"flagKey"`
	DefaultValue any               `json:"defaultValue"`
	Environment  string             `json:"environment,omitempty"`
	Context      EvaluationContext  `json:"context,omitempty"`
}

// Evaluate resolves a flag against the given evaluation context.
// This implements the OpenFeature evaluation logic per spec sections 2.3-2.5.
func Evaluate(flag *models.Flag, envKey string, ctx EvaluationContext) ResolutionDetail {
	// Build flag metadata
	metadata := map[string]any{
		MetaFlagKey: flag.Key,
	}
	if flag.Version > 0 {
		metadata[MetaFlagVersion] = flag.Version
	}
	if envKey != "" {
		metadata[MetaEnvironment] = envKey
	}

	// Flag is disabled — return the default variation with DISABLED reason
	if !flag.Enabled {
		if flag.DefaultRule != nil {
			return ResolutionDetail{
				Value:        getVariationValueByID(flag, flag.DefaultRule.VariationID),
				Variant:      getVariationLabelByID(flag, flag.DefaultRule.VariationID),
				Reason:       ReasonDisabled,
				FlagMetadata: metadata,
			}
		}
		// Disabled with no default rule — error
		return ResolutionDetail{
			Reason:       ReasonError,
			ErrorCode:    ErrParseError,
			ErrorMessage: "flag is disabled and has no default rule",
			FlagMetadata: metadata,
		}
	}

	// Try targeting rules first (in order — first match wins)
	for _, rule := range flag.Targeting {
		if matchesAllConditions(rule.Conditions, ctx) {
			return ResolutionDetail{
				Value:        getVariationValueByID(flag, rule.VariationID),
				Variant:      getVariationLabelByID(flag, rule.VariationID),
				Reason:       ReasonTargetingMatch,
				FlagMetadata: metadata,
			}
		}
	}

	// Apply default rule (with percentage rollout if configured)
	if flag.DefaultRule != nil {
		if len(flag.DefaultRule.Percentage) > 0 {
			variationID := percentageBucket(flag.Key, envKey, ctx.TargetingKey, flag.DefaultRule.Percentage)
			return ResolutionDetail{
				Value:        getVariationValueByID(flag, variationID),
				Variant:      getVariationLabelByID(flag, variationID),
				Reason:       ReasonSplit,
				FlagMetadata: metadata,
			}
		}
		return ResolutionDetail{
			Value:        getVariationValueByID(flag, flag.DefaultRule.VariationID),
			Variant:      getVariationLabelByID(flag, flag.DefaultRule.VariationID),
			Reason:       ReasonDefault,
			FlagMetadata: metadata,
		}
	}

	// No default rule — error
	return ResolutionDetail{
		Reason:       ReasonError,
		ErrorCode:    ErrParseError,
		ErrorMessage: "flag has no default rule configured",
		FlagMetadata: metadata,
	}
}

// EvaluateWithType resolves a flag and validates the return type matches the expected type.
// Returns TYPE_MISMATCH error if the resolved value doesn't match the requested type.
func EvaluateWithType(flag *models.Flag, envKey string, ctx EvaluationContext, expectedType models.FlagType) ResolutionDetail {
	detail := Evaluate(flag, envKey, ctx)

	// Don't type-check errors
	if detail.Reason == ReasonError {
		return detail
	}

	if !ValidateType(detail.Value, expectedType) {
		return ResolutionDetail{
			Value:        nil,
			Variant:      detail.Variant,
			Reason:       ReasonError,
			ErrorCode:    ErrTypeMismatch,
			ErrorMessage: fmt.Sprintf("expected %s, got %T", expectedType, detail.Value),
			FlagMetadata: detail.FlagMetadata,
		}
	}

	return detail
}

// EvaluateWithSecrets resolves a flag and resolves any secret references.
func EvaluateWithSecrets(flag *models.Flag, envKey string, ctx EvaluationContext, resolver SecretResolver) ResolutionDetail {
	detail := Evaluate(flag, envKey, ctx)
	if resolver == nil || detail.Value == nil || detail.Reason == ReasonError {
		return detail
	}
	resolved, err := resolveSecretValue(detail.Value, resolver)
	if err != nil {
		return ResolutionDetail{
			Reason:       ReasonError,
			ErrorCode:    ErrSecretResolution,
			ErrorMessage: err.Error(),
			FlagMetadata: detail.FlagMetadata,
		}
	}
	detail.Value = resolved
	return detail
}

// ValidateType checks if a value matches the expected OpenFeature flag type.
func ValidateType(val any, expectedType models.FlagType) bool {
	switch expectedType {
	case models.FlagTypeBoolean:
		_, ok := val.(bool)
		return ok
	case models.FlagTypeString:
		_, ok := val.(string)
		return ok
	case models.FlagTypeNumber:
		switch val.(type) {
		case float64, float32, int, int64, int32, json.Number:
			return true
		}
		return false
	case models.FlagTypeObject:
		// Objects can be maps or nil — but not primitives
		switch val.(type) {
		case map[string]any, []any, nil:
			return true
		}
		return false
	default:
		return false
	}
}

// resolveSecretValue resolves a {"$secret": "KEY"} reference to its decrypted value.
func resolveSecretValue(val any, resolver SecretResolver) (any, error) {
	m, ok := val.(map[string]any)
	if !ok {
		return val, nil
	}
	secretKey, hasRef := m["$secret"]
	if !hasRef {
		return val, nil
	}
	keyStr, ok := secretKey.(string)
	if !ok {
		return nil, fmt.Errorf("$secret value must be a string")
	}
	decrypted, err := resolver(keyStr)
	if err != nil {
		return nil, fmt.Errorf("secret reference resolution failed")
	}
	return decrypted, nil
}

// --- Targeting rule evaluation ---

func matchesAllConditions(conditions []models.Condition, ctx EvaluationContext) bool {
	if len(conditions) == 0 {
		return false
	}
	for _, cond := range conditions {
		if !matchesCondition(cond, ctx) {
			return false
		}
	}
	return true
}

func matchesCondition(cond models.Condition, ctx EvaluationContext) bool {
	if cond.Attribute == "" {
		return false
	}
	var attrVal any
	if cond.Attribute == "targetingKey" {
		attrVal = ctx.TargetingKey
	} else {
		attrVal = ctx.Attributes[cond.Attribute]
	}
	if attrVal == nil {
		return false
	}
	// Reject complex types for string-based operators
	switch attrVal.(type) {
	case []any, map[string]any:
		// Only allow complex types for type-agnostic operators (true/false/empty/not_empty)
		// For all string operators, complex types are rejected to prevent fmt.Sprintf false matches
		if cond.Operator != "true" && cond.Operator != "TRUE" &&
			cond.Operator != "false" && cond.Operator != "FALSE" &&
			cond.Operator != "empty" && cond.Operator != "EMPTY" &&
			cond.Operator != "not_empty" && cond.Operator != "NOT_EMPTY" {
			return false
		}
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
		return attrVal == true
	case "false", "FALSE":
		return attrVal == false
	case "empty", "EMPTY":
		return attrStr == ""
	case "not_empty", "NOT_EMPTY":
		return attrStr != ""
	case "regex", "REGEX":
		for _, v := range cond.Values {
			if len(v) > 500 {
				continue // reject overly long patterns
			}
			re, err := regexp.Compile(v)
			if err == nil && re.MatchString(attrStr) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// percentageBucket determines which variation a key falls into using
// deterministic SHA-256 hash-based bucketing (OpenFeature spec compliant).
func percentageBucket(flagKey, envKey, targetingKey string, percentages map[string]int) string {
	if len(percentages) == 0 {
		return ""
	}
	variationIDs := make([]string, 0, len(percentages))
	for id := range percentages {
		variationIDs = append(variationIDs, id)
	}
	sort.Strings(variationIDs)

	// Validate percentages: all must be >= 0 and sum to 100
	total := 0
	for _, id := range variationIDs {
		p := percentages[id]
		if p < 0 {
			return variationIDs[0]
		}
		total += p
	}
	if total != 100 {
		// Misconfigured rollout — fall back to first variation rather than silently distributing incorrectly
		return variationIDs[0]
	}

	hashInput := fmt.Sprintf("%s:%s:%s", flagKey, envKey, targetingKey)
	h := sha256.Sum256([]byte(hashInput))
	bucket := binary.BigEndian.Uint64(h[:8]) % 100

	cumulative := 0
	for _, id := range variationIDs {
		cumulative += percentages[id]
		if int(bucket) < cumulative {
			return id
		}
	}
	return variationIDs[0]
}

// --- Helpers ---

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

// getVariationValueByIDWithErr is like getVariationValueByID but returns an error
// when the variation value JSON is malformed or the variation ID is not found.
func getVariationValueByIDWithErr(flag *models.Flag, variationID string) (any, error) {
	for _, v := range flag.Variations {
		if v.ID == variationID {
			var val any
			if err := json.Unmarshal(v.Value, &val); err != nil {
				return nil, fmt.Errorf("malformed variation value")
			}
			return val, nil
		}
	}
	return nil, fmt.Errorf("variation %q not found", variationID)
}

func getVariationLabelByID(flag *models.Flag, variationID string) string {
	for _, v := range flag.Variations {
		if v.ID == variationID {
			return v.Label
		}
	}
	return ""
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
