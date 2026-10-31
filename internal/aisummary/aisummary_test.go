package aisummary_test

import (
	"context"
	"strings"
	"testing"

	"rdpshot/internal/aisummary"
)

func sampleInput() aisummary.SummaryInput {
	return aisummary.SummaryInput{
		ScanName:       "Q4 Internal Audit",
		Engagement:     "ACME Corp",
		ScannedAt:      "2026-10-31",
		HostsOpen:      15,
		HostsTotal:     50,
		CriticalCount:  3,
		HighCount:      7,
		MediumCount:    12,
		LowCount:       5,
		HardeningScore: 42,
		HardeningGrade: "F",
		ValidCreds:     2,
		CVEs:           []string{"CVE-2019-0708"},
		Compliance:     map[string]int{"CIS": 55, "PCI-DSS": 40},
		KeyFindings:    []string{"nla-not-required", "bluekeep-cve-2019-0708"},
	}
}

func TestGenerate_TemplateFallback_EN(t *testing.T) {
	cfg := aisummary.LLMConfig{Provider: aisummary.ProviderNone, Language: "en"}
	result, err := aisummary.Generate(context.Background(), cfg, sampleInput())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty summary")
	}
	if !strings.Contains(result, "Executive Summary") {
		t.Error("expected 'Executive Summary' in output")
	}
	if !strings.Contains(result, "critical") {
		t.Error("expected risk level in output")
	}
	if !strings.Contains(result, "CVE-2019-0708") {
		t.Error("expected CVE mention in output")
	}
}

func TestGenerate_TemplateFallback_TR(t *testing.T) {
	cfg := aisummary.LLMConfig{Provider: aisummary.ProviderNone, Language: "tr"}
	result, err := aisummary.Generate(context.Background(), cfg, sampleInput())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if !strings.Contains(result, "Yönetici") {
		t.Error("expected Turkish header in output")
	}
}

func TestGenerate_DefaultFallbackWhenProviderEmpty(t *testing.T) {
	cfg := aisummary.LLMConfig{} // empty provider → falls through to template
	result, err := aisummary.Generate(context.Background(), cfg, sampleInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty fallback summary")
	}
}

func TestLLMConfig_Redacted(t *testing.T) {
	cfg := aisummary.LLMConfig{
		Provider: aisummary.ProviderOpenAI,
		APIKey:   "sk-supersecretkey",
		Model:    "gpt-4o",
	}
	red := cfg.Redacted()
	if red.APIKey != "" {
		t.Errorf("expected empty APIKey after Redacted(), got %q", red.APIKey)
	}
	if red.Model != "gpt-4o" {
		t.Error("non-secret field should be preserved after Redacted()")
	}
}

func TestGenerate_NilContext(t *testing.T) {
	cfg := aisummary.LLMConfig{Provider: aisummary.ProviderNone}
	//nolint:staticcheck // intentional nil context test
	result, err := aisummary.Generate(nil, cfg, sampleInput())
	if err != nil {
		t.Fatalf("unexpected error with nil context: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty output")
	}
}
