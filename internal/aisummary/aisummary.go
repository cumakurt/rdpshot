// Package aisummary generates a professional executive summary from scan data
// using a local (Ollama) or cloud (OpenAI / Anthropic / Gemini) LLM.
//
// If no LLM is configured the package falls back to a deterministic
// template-based summary so the feature degrades gracefully.
package aisummary

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider selects which LLM backend to use.
type Provider string

const (
	ProviderOllama    Provider = "ollama"
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderGemini    Provider = "gemini"
	ProviderNone      Provider = "none" // template-only fallback
)

// LLMConfig holds the LLM connection settings.  APIKey is stored in the
// settings table and must be redacted before returning over the API.
type LLMConfig struct {
	Provider  Provider `json:"provider"`
	BaseURL   string   `json:"base_url,omitempty"`   // Ollama URL or OpenAI-compatible endpoint
	Model     string   `json:"model,omitempty"`
	APIKey    string   `json:"api_key,omitempty"`    // REDACTED in API responses
	Language  string   `json:"language,omitempty"`   // "en" or "tr" (default: "en")
	TimeoutSec int     `json:"timeout_sec,omitempty"` // default 60
}

// Redacted returns a copy with secrets cleared.
func (c LLMConfig) Redacted() LLMConfig {
	c.APIKey = ""
	return c
}

// SummaryInput is the structured scan data passed to the LLM prompt.
type SummaryInput struct {
	ScanName      string   `json:"scan_name"`
	Engagement    string   `json:"engagement"`
	ScannedAt     string   `json:"scanned_at"`
	HostsOpen     int      `json:"hosts_open"`
	HostsTotal    int      `json:"hosts_total"`
	CriticalCount int      `json:"critical_count"`
	HighCount     int      `json:"high_count"`
	MediumCount   int      `json:"medium_count"`
	LowCount      int      `json:"low_count"`
	HardeningScore int     `json:"hardening_score"`
	HardeningGrade string  `json:"hardening_grade"`
	ValidCreds    int      `json:"valid_creds"`
	CVEs          []string `json:"cves,omitempty"`
	Compliance    map[string]int `json:"compliance,omitempty"` // standard → score
	KeyFindings   []string `json:"key_findings,omitempty"`
}

// Generate calls the configured LLM and returns an executive summary string.
// It falls back to a template-based summary if the LLM is unavailable.
func Generate(ctx context.Context, cfg LLMConfig, input SummaryInput) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 60
	}
	if cfg.Language == "" {
		cfg.Language = "en"
	}

	prompt := buildPrompt(cfg.Language, input)

	switch cfg.Provider {
	case ProviderOllama:
		return callOllama(ctx, cfg, prompt)
	case ProviderOpenAI:
		return callOpenAICompat(ctx, cfg, prompt, "https://api.openai.com/v1/chat/completions")
	case ProviderAnthropic:
		return callAnthropic(ctx, cfg, prompt)
	case ProviderGemini:
		return callGemini(ctx, cfg, prompt)
	default:
		// Graceful fallback: deterministic template summary.
		return templateSummary(cfg.Language, input), nil
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Prompt builder
// ─────────────────────────────────────────────────────────────────────────────

func buildPrompt(lang string, inp SummaryInput) string {
	if lang == "tr" {
		return buildPromptTR(inp)
	}
	return buildPromptEN(inp)
}

func buildPromptEN(inp SummaryInput) string {
	var b strings.Builder
	b.WriteString("You are a senior cybersecurity consultant. Write a professional executive summary " +
		"(3–4 paragraphs, no bullet points) for the following RDP security audit results. " +
		"Focus on business risk, not technical jargon. Be concise and authoritative.\n\n")
	b.WriteString("AUDIT DATA:\n")
	fmt.Fprintf(&b, "- Scan: %s (Engagement: %s, Date: %s)\n", inp.ScanName, inp.Engagement, inp.ScannedAt)
	fmt.Fprintf(&b, "- Hosts scanned: %d total, %d open RDP services\n", inp.HostsTotal, inp.HostsOpen)
	fmt.Fprintf(&b, "- Findings: %d critical, %d high, %d medium, %d low\n",
		inp.CriticalCount, inp.HighCount, inp.MediumCount, inp.LowCount)
	fmt.Fprintf(&b, "- Hardening grade: %s (%d/100)\n", inp.HardeningGrade, inp.HardeningScore)
	fmt.Fprintf(&b, "- Valid credentials discovered: %d\n", inp.ValidCreds)
	if len(inp.CVEs) > 0 {
		fmt.Fprintf(&b, "- CVEs confirmed: %s\n", strings.Join(inp.CVEs, ", "))
	}
	if len(inp.Compliance) > 0 {
		b.WriteString("- Compliance scores: ")
		for std, score := range inp.Compliance {
			fmt.Fprintf(&b, "%s=%d%% ", std, score)
		}
		b.WriteString("\n")
	}
	if len(inp.KeyFindings) > 0 {
		b.WriteString("- Key findings: ")
		b.WriteString(strings.Join(inp.KeyFindings, "; "))
		b.WriteString("\n")
	}
	b.WriteString("\nExecutive Summary:\n")
	return b.String()
}

func buildPromptTR(inp SummaryInput) string {
	var b strings.Builder
	b.WriteString("Kıdemli bir siber güvenlik danışmanısınız. Aşağıdaki RDP güvenlik denetimi sonuçları için " +
		"profesyonel bir yönetici özeti yazın (3–4 paragraf, madde işareti kullanmayın). " +
		"Teknik jargon yerine iş riskine odaklanın.\n\n")
	b.WriteString("DENETİM VERİLERİ:\n")
	fmt.Fprintf(&b, "- Tarama: %s (Müşteri: %s, Tarih: %s)\n", inp.ScanName, inp.Engagement, inp.ScannedAt)
	fmt.Fprintf(&b, "- Taranan host: toplam %d, açık RDP servisi %d\n", inp.HostsTotal, inp.HostsOpen)
	fmt.Fprintf(&b, "- Bulgular: %d kritik, %d yüksek, %d orta, %d düşük\n",
		inp.CriticalCount, inp.HighCount, inp.MediumCount, inp.LowCount)
	fmt.Fprintf(&b, "- Sertleştirme notu: %s (%d/100)\n", inp.HardeningGrade, inp.HardeningScore)
	fmt.Fprintf(&b, "- Bulunan geçerli kimlik: %d\n", inp.ValidCreds)
	if len(inp.CVEs) > 0 {
		fmt.Fprintf(&b, "- Doğrulanan CVE'ler: %s\n", strings.Join(inp.CVEs, ", "))
	}
	b.WriteString("\nYönetici Özeti:\n")
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// LLM backends
// ─────────────────────────────────────────────────────────────────────────────

func callOllama(ctx context.Context, cfg LLMConfig, prompt string) (string, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	model := cfg.Model
	if model == "" {
		model = "llama3"
	}

	payload := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}
	return doPost(ctx, baseURL+"/api/generate", "", cfg.TimeoutSec, payload, func(body []byte) (string, error) {
		var resp struct {
			Response string `json:"response"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("ollama: parse response: %w", err)
		}
		if resp.Error != "" {
			return "", fmt.Errorf("ollama: %s", resp.Error)
		}
		return strings.TrimSpace(resp.Response), nil
	})
}

func callOpenAICompat(ctx context.Context, cfg LLMConfig, prompt, endpoint string) (string, error) {
	model := cfg.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens":  1200,
		"temperature": 0.3,
	}
	return doPost(ctx, endpoint, "Bearer "+cfg.APIKey, cfg.TimeoutSec, payload, func(body []byte) (string, error) {
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Error *struct{ Message string `json:"message"` } `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("openai: parse response: %w", err)
		}
		if resp.Error != nil {
			return "", fmt.Errorf("openai: %s", resp.Error.Message)
		}
		if len(resp.Choices) == 0 {
			return "", fmt.Errorf("openai: no choices returned")
		}
		return strings.TrimSpace(resp.Choices[0].Message.Content), nil
	})
}

func callAnthropic(ctx context.Context, cfg LLMConfig, prompt string) (string, error) {
	model := cfg.Model
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	payload := map[string]any{
		"model":      model,
		"max_tokens": 1200,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	// Anthropic uses x-api-key header instead of Authorization Bearer.
	return doPost(ctx, "https://api.anthropic.com/v1/messages", "x-api-key:"+cfg.APIKey, cfg.TimeoutSec, payload, func(body []byte) (string, error) {
		var resp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Error *struct{ Message string `json:"message"` } `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("anthropic: parse response: %w", err)
		}
		if resp.Error != nil {
			return "", fmt.Errorf("anthropic: %s", resp.Error.Message)
		}
		if len(resp.Content) == 0 {
			return "", fmt.Errorf("anthropic: empty content")
		}
		return strings.TrimSpace(resp.Content[0].Text), nil
	})
}

func callGemini(ctx context.Context, cfg LLMConfig, prompt string) (string, error) {
	model := cfg.Model
	if model == "" {
		model = "gemini-1.5-flash"
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, cfg.APIKey)
	payload := map[string]any{
		"contents": []map[string]any{
			{"parts": []map[string]string{{"text": prompt}}},
		},
	}
	return doPost(ctx, url, "", cfg.TimeoutSec, payload, func(body []byte) (string, error) {
		var resp struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			Error *struct{ Message string `json:"message"` } `json:"error"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("gemini: parse response: %w", err)
		}
		if resp.Error != nil {
			return "", fmt.Errorf("gemini: %s", resp.Error.Message)
		}
		if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
			return "", fmt.Errorf("gemini: empty response")
		}
		return strings.TrimSpace(resp.Candidates[0].Content.Parts[0].Text), nil
	})
}

// doPost is the shared HTTP POST helper.
func doPost(ctx context.Context, url, authHeader string, timeoutSec int, payload any, parse func([]byte) (string, error)) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "x-api-key:") {
			req.Header.Set("x-api-key", strings.TrimPrefix(authHeader, "x-api-key:"))
			req.Header.Set("anthropic-version", "2023-06-01")
		} else {
			req.Header.Set("Authorization", authHeader)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}
	return parse(body)
}

// ─────────────────────────────────────────────────────────────────────────────
// Template fallback
// ─────────────────────────────────────────────────────────────────────────────

func templateSummary(lang string, inp SummaryInput) string {
	if lang == "tr" {
		return templateSummaryTR(inp)
	}
	return templateSummaryEN(inp)
}

func templateSummaryEN(inp SummaryInput) string {
	riskLevel := "moderate"
	if inp.CriticalCount > 0 || inp.ValidCreds > 0 {
		riskLevel = "critical"
	} else if inp.HighCount > 3 {
		riskLevel = "high"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "## Executive Summary — %s\n\n", inp.ScanName)
	fmt.Fprintf(&b,
		"The RDP security assessment conducted on %s for the %q engagement revealed a **%s** "+
			"overall risk posture. Of the %d hosts scanned, %d exposed active Remote Desktop services. "+
			"The environment received a hardening grade of **%s** (%d/100), indicating significant "+
			"gaps in endpoint security configuration.\n\n",
		inp.ScannedAt, inp.Engagement, riskLevel,
		inp.HostsTotal, inp.HostsOpen, inp.HardeningGrade, inp.HardeningScore)

	fmt.Fprintf(&b,
		"The assessment identified **%d critical**, %d high, %d medium, and %d low-severity findings. ",
		inp.CriticalCount, inp.HighCount, inp.MediumCount, inp.LowCount)
	if inp.ValidCreds > 0 {
		fmt.Fprintf(&b,
			"Critically, **%d sets of valid credentials** were confirmed, demonstrating that an "+
				"attacker could achieve immediate, authenticated access to production systems. ", inp.ValidCreds)
	}
	if len(inp.CVEs) > 0 {
		fmt.Fprintf(&b, "Known vulnerabilities including %s were confirmed, presenting pre-authentication "+
			"remote code execution risks that could result in full system compromise.\n\n",
			strings.Join(inp.CVEs, " and "))
	} else {
		b.WriteString("\n\n")
	}

	b.WriteString("Immediate remediation is required. Priority actions include: enforcing Network Level " +
		"Authentication (NLA) across all RDP-enabled endpoints, retiring TLS 1.0/1.1 configurations, " +
		"patching all identified CVEs, and rotating any compromised credentials. A phased remediation " +
		"timeline with clear ownership should be established within 72 hours of this report.\n\n")

	fmt.Fprintf(&b,
		"*Generated by RDPShot on %s. This summary is auto-generated; consult the full technical "+
			"report for complete findings.*", time.Now().UTC().Format("2006-01-02"))
	return b.String()
}

func templateSummaryTR(inp SummaryInput) string {
	risk := "orta"
	if inp.CriticalCount > 0 || inp.ValidCreds > 0 {
		risk = "kritik"
	} else if inp.HighCount > 3 {
		risk = "yüksek"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Yönetici Özeti — %s\n\n", inp.ScanName)
	fmt.Fprintf(&b,
		"%s tarihinde %q müşterisi için gerçekleştirilen RDP güvenlik denetimi, genel risk "+
			"durumunun **%s** düzeyde olduğunu ortaya koymuştur. Taranan %d host'un %d'i aktif "+
			"Uzak Masaüstü servisi barındırmaktadır. Ortam, sertleştirme değerlendirmesinde "+
			"**%s** (%d/100) notu almış; bu durum uç nokta güvenlik yapılandırmasında ciddi "+
			"eksiklikler bulunduğuna işaret etmektedir.\n\n",
		inp.ScannedAt, inp.Engagement, risk,
		inp.HostsTotal, inp.HostsOpen, inp.HardeningGrade, inp.HardeningScore)

	fmt.Fprintf(&b,
		"Denetimde **%d kritik**, %d yüksek, %d orta ve %d düşük önem düzeyinde bulgu tespit edilmiştir. ",
		inp.CriticalCount, inp.HighCount, inp.MediumCount, inp.LowCount)
	if inp.ValidCreds > 0 {
		fmt.Fprintf(&b,
			"**%d adet geçerli kimlik bilgisi** doğrulanmış olup bu durum bir saldırganın üretim "+
				"sistemlere kimlik doğrulamalı erişim sağlayabileceğini kanıtlamaktadır. ", inp.ValidCreds)
	}
	b.WriteString("\n\n")
	b.WriteString("Acil iyileştirme adımları şunlardır: tüm RDP uç noktalarında Ağ Düzeyi Kimlik " +
		"Doğrulaması (NLA) zorunlu kılınması, TLS 1.0/1.1 yapılandırmalarının kaldırılması, " +
		"tespit edilen tüm CVE'lerin yamalanması ve ele geçirilen kimlik bilgilerinin rotasyonu. " +
		"Bu raporun tesliminden itibaren 72 saat içinde net sahiplik atamalarıyla aşamalı bir " +
		"iyileştirme zaman çizelgesi oluşturulmalıdır.\n\n")
	fmt.Fprintf(&b,
		"*RDPShot tarafından %s tarihinde otomatik olarak oluşturulmuştur.*",
		time.Now().UTC().Format("02.01.2006"))
	return b.String()
}
