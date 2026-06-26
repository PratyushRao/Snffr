package rules

import (
	"testing"

	"snffr/manager/internal/ai"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func normalFlow() ai.FlowFeatures {
	return ai.FlowFeatures{
		DestinationPort:       80,
		FlowDuration:          1_000,
		TotalFwdPackets:       10,
		TotalLengthFwdPackets: 1_000,
		FlowBytesPerSecond:    100,
		FlowPacketsPerSecond:  10,
		AveragePacketSize:     100,
	}
}

// ── Score tests ───────────────────────────────────────────────────────────────

func TestScore_NormalFlow_ZeroRisk(t *testing.T) {
	e := NewEngine()
	got := e.Score(normalFlow())
	if got != 0 {
		t.Errorf("normal flow score = %d, want 0", got)
	}
}

func TestScore_HighFlowBytesPerSecond(t *testing.T) {
	e := NewEngine()
	f := normalFlow()
	f.FlowBytesPerSecond = thresholdFlowBytesPerSecond + 1

	got := e.Score(f)
	if got < riskHighFlowBytes {
		t.Errorf("high bytes/s risk = %d, want >= %d", got, riskHighFlowBytes)
	}
}

func TestScore_HighFlowPacketsPerSecond(t *testing.T) {
	e := NewEngine()
	f := normalFlow()
	f.FlowPacketsPerSecond = thresholdFlowPacketsPerSecond + 1

	got := e.Score(f)
	if got < riskHighFlowPackets {
		t.Errorf("high pkts/s risk = %d, want >= %d", got, riskHighFlowPackets)
	}
}

func TestScore_HighTotalFwdPackets(t *testing.T) {
	e := NewEngine()
	f := normalFlow()
	f.TotalFwdPackets = thresholdTotalFwdPackets + 1

	got := e.Score(f)
	if got < riskHighTotalFwdPackets {
		t.Errorf("high fwd-packets risk = %d, want >= %d", got, riskHighTotalFwdPackets)
	}
}

func TestScore_LargeAveragePacketSize(t *testing.T) {
	e := NewEngine()
	f := normalFlow()
	f.AveragePacketSize = thresholdAveragePacketSize + 1

	got := e.Score(f)
	if got < riskLargeAvgPacket {
		t.Errorf("large avg-packet risk = %d, want >= %d", got, riskLargeAvgPacket)
	}
}

func TestScore_AllRulesFired_MaxRisk(t *testing.T) {
	e := NewEngine()
	f := ai.FlowFeatures{
		FlowBytesPerSecond:   thresholdFlowBytesPerSecond + 1,
		FlowPacketsPerSecond: thresholdFlowPacketsPerSecond + 1,
		TotalFwdPackets:      thresholdTotalFwdPackets + 1,
		AveragePacketSize:    thresholdAveragePacketSize + 1,
	}

	want := riskHighFlowBytes + riskHighFlowPackets + riskHighTotalFwdPackets + riskLargeAvgPacket
	got := e.Score(f)
	if got != want {
		t.Errorf("all-rules-fired score = %d, want %d", got, want)
	}
}

// ── NewEngineWithRules ────────────────────────────────────────────────────────

func TestNewEngineWithRules_CustomRule(t *testing.T) {
	customRules := []Rule{
		{
			Name:      "TestRule",
			RiskDelta: 42,
			Match:     func(f ai.FlowFeatures) bool { return f.DestinationPort == 9999 },
		},
	}

	e := NewEngineWithRules(customRules)

	f := normalFlow()
	if e.Score(f) != 0 {
		t.Error("custom rule should not fire on normal flow")
	}

	f.DestinationPort = 9999
	if got := e.Score(f); got != 42 {
		t.Errorf("custom rule score = %d, want 42", got)
	}
}

// ── Thread safety ─────────────────────────────────────────────────────────────

func TestScore_ConcurrentSafe(t *testing.T) {
	e := NewEngine()
	f := normalFlow()

	const goroutines = 100
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_ = e.Score(f)
			done <- struct{}{}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
