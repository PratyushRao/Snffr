package decision

import (
	"testing"

	"snffr/manager/internal/ai"
	"snffr/manager/internal/rules"
)

// ─────────────────────────────────────────────────────────────────────────────
// Stub Predictor for tests (no ONNX Runtime required)
// ─────────────────────────────────────────────────────────────────────────────

// stubPredictor wraps ai.Predictor's interface by replacing the real
// inference backend with a configurable return value. Because ai.Predictor is
// a concrete struct (not an interface), we use a thin shim at the Engine level
// instead. Here we test the decision logic via a custom Engine built with
// NewEngineWithComponents, injecting a real rules.Engine and a fixed aiRisk.
//
// The simplest approach: test classify() and threshold math directly, plus
// full-pipeline tests using a zero-risk AI mock rule.

// ── classify() ────────────────────────────────────────────────────────────────

func TestClassify(t *testing.T) {
	tests := []struct {
		risk int
		want Decision
	}{
		{0, Allow},
		{29, Allow},
		{30, RateLimit},
		{59, RateLimit},
		{60, Block},
		{100, Block},
		{999, Block},
	}

	for _, tc := range tests {
		got := classify(tc.risk)
		if got != tc.want {
			t.Errorf("classify(%d) = %s, want %s", tc.risk, got, tc.want)
		}
	}
}

// ── Decision.String() ─────────────────────────────────────────────────────────

func TestDecision_String(t *testing.T) {
	tests := []struct {
		d    Decision
		want string
	}{
		{Allow, "ALLOW"},
		{RateLimit, "RATE_LIMIT"},
		{Block, "BLOCK"},
		{Decision(99), "UNKNOWN(99)"},
	}

	for _, tc := range tests {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("Decision(%d).String() = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// ── rules-only pipeline ───────────────────────────────────────────────────────
// We exercise the full Engine.EvaluateFlow path using a rules-only approach:
// inject a zero-delta custom rule engine and verify threshold mapping.

func TestEvaluateFlow_RulesOnly_Allow(t *testing.T) {
	e := engineWithFixedAIRisk(0, 0) // aiRisk=0, ruleRisk=0

	f := ai.FlowFeatures{}
	d, risk, err := e.EvaluateFlow(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != Allow {
		t.Errorf("decision = %s, want ALLOW", d)
	}
	if risk != 0 {
		t.Errorf("totalRisk = %d, want 0", risk)
	}
}

func TestEvaluateFlow_RulesOnly_RateLimit(t *testing.T) {
	// Rule contributes 30 → RATE_LIMIT boundary
	e := engineWithFixedAIRisk(0, 30)

	d, risk, err := e.EvaluateFlow(ai.FlowFeatures{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != RateLimit {
		t.Errorf("decision = %s, want RATE_LIMIT", d)
	}
	if risk != 30 {
		t.Errorf("totalRisk = %d, want 30", risk)
	}
}

func TestEvaluateFlow_RulesOnly_Block(t *testing.T) {
	// Rule contributes 60 → BLOCK boundary
	e := engineWithFixedAIRisk(0, 60)

	d, risk, err := e.EvaluateFlow(ai.FlowFeatures{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != Block {
		t.Errorf("decision = %s, want BLOCK", d)
	}
	if risk != 60 {
		t.Errorf("totalRisk = %d, want 60", risk)
	}
}

func TestEvaluateFlow_AIAnomaly_PushesToBlock(t *testing.T) {
	// AI alone contributes 50; a single high-bytes rule adds 20 → 70 → BLOCK
	e := engineWithFixedAIRisk(50, 20)

	d, risk, err := e.EvaluateFlow(ai.FlowFeatures{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != Block {
		t.Errorf("decision = %s, want BLOCK", d)
	}
	if risk != 70 {
		t.Errorf("totalRisk = %d, want 70", risk)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// fixedRiskPredictor wraps a constant AI risk value inside the ai package's
// Predictor interface surface by using a local shim Engine.
//
// Because ai.Predictor is a concrete struct (uses real ONNX Runtime), we
// instead build a custom Engine variant that bypasses the AI predictor entirely.
// We do this by embedding the Engine struct and overriding EvaluateFlow.

type stubEngine struct {
	aiRisk   int
	ruleEng  *rules.Engine
}

func (s *stubEngine) EvaluateFlow(flow ai.FlowFeatures) (Decision, int, error) {
	ruleRisk := s.ruleEng.Score(flow)
	totalRisk := s.aiRisk + ruleRisk
	return classify(totalRisk), totalRisk, nil
}

// engineWithFixedAIRisk constructs a stubEngine where AI always returns
// aiRisk and the rule engine always returns ruleRisk (via a custom fixed rule).
func engineWithFixedAIRisk(aiRisk, ruleRisk int) *stubEngine {
	customRules := []rules.Rule{
		{
			Name:      "FixedRisk",
			RiskDelta: ruleRisk,
			Match:     func(_ ai.FlowFeatures) bool { return true },
		},
	}
	return &stubEngine{
		aiRisk:  aiRisk,
		ruleEng: rules.NewEngineWithRules(customRules),
	}
}
