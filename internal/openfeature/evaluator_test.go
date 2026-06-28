package openfeature

import (
	"encoding/json"
	"testing"

	"github.com/dovocoder/reflag/internal/models"
)

func makeFlag() *models.Flag {
	return &models.Flag{
		Key:     "segmented-flag",
		Type:    models.FlagTypeString,
		Enabled: true,
		Variations: []models.Variation{
			{ID: "v-default", Label: "Default", Value: json.RawMessage(`"default"`)},
			{ID: "v-target", Label: "Target", Value: json.RawMessage(`"target"`)},
		},
		DefaultRule: &models.DefaultRule{VariationID: "v-default"},
	}
}

func betaSegmentResolver(id string) ([]models.Condition, bool) {
	if id == "beta-segment" {
		return []models.Condition{{
			ID:        "c1",
			Attribute: "email",
			Operator:  "ends_with",
			Values:    []string{"@beta.com"},
		}}, true
	}
	return nil, false
}

func TestEvaluateSegmentMatch(t *testing.T) {
	flag := makeFlag()
	flag.Targeting = []models.TargetingRule{{
		ID:          "rule-1",
		Name:        "beta users",
		SegmentIDs:  []string{"beta-segment"},
		VariationID: "v-target",
	}}

	detail := Evaluate(flag, "", EvaluationContext{Attributes: map[string]any{"email": "alice@beta.com"}}, betaSegmentResolver)
	if detail.Reason != ReasonTargetingMatch {
		t.Fatalf("expected TARGETING_MATCH, got %s", detail.Reason)
	}
	if detail.Value != "target" {
		t.Fatalf("expected target value, got %v", detail.Value)
	}
}

func TestEvaluateSegmentNoMatch(t *testing.T) {
	flag := makeFlag()
	flag.Targeting = []models.TargetingRule{{
		ID:          "rule-1",
		Name:        "beta users",
		SegmentIDs:  []string{"beta-segment"},
		VariationID: "v-target",
	}}

	detail := Evaluate(flag, "", EvaluationContext{Attributes: map[string]any{"email": "alice@other.com"}}, betaSegmentResolver)
	if detail.Reason != ReasonDefault {
		t.Fatalf("expected DEFAULT, got %s", detail.Reason)
	}
	if detail.Value != "default" {
		t.Fatalf("expected default value, got %v", detail.Value)
	}
}

func TestEvaluateSegmentMissing(t *testing.T) {
	flag := makeFlag()
	flag.Targeting = []models.TargetingRule{{
		ID:          "rule-1",
		Name:        "beta users",
		SegmentIDs:  []string{"missing-segment"},
		VariationID: "v-target",
	}}

	detail := Evaluate(flag, "", EvaluationContext{Attributes: map[string]any{"email": "alice@beta.com"}}, betaSegmentResolver)
	if detail.Reason != ReasonDefault {
		t.Fatalf("expected DEFAULT when segment missing, got %s", detail.Reason)
	}
}

func TestEvaluateInlineAndSegmentConditions(t *testing.T) {
	flag := makeFlag()
	flag.Targeting = []models.TargetingRule{{
		ID:   "rule-1",
		Name: "beta + internal",
		Conditions: []models.Condition{{
			ID:        "c1",
			Attribute: "host",
			Operator:  "eq",
			Values:    []string{"internal"},
		}},
		SegmentIDs:  []string{"beta-segment"},
		VariationID: "v-target",
	}}

	// Both match.
	detail := Evaluate(flag, "", EvaluationContext{Attributes: map[string]any{
		"email": "alice@beta.com",
		"host":  "internal",
	}}, betaSegmentResolver)
	if detail.Value != "target" {
		t.Fatalf("expected target when inline and segment match, got %v", detail.Value)
	}

	// Inline matches but segment does not.
	detail = Evaluate(flag, "", EvaluationContext{Attributes: map[string]any{
		"email": "alice@other.com",
		"host":  "internal",
	}}, betaSegmentResolver)
	if detail.Value != "default" {
		t.Fatalf("expected default when segment fails, got %v", detail.Value)
	}
}
