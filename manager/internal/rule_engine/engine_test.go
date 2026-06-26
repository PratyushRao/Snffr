package rule_engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"snffr/manager/proto"
)

func TestMatchIP(t *testing.T) {
	tests := []struct {
		ruleIP   string
		packetIP string
		expected bool
	}{
		{"", "192.168.1.5", true},
		{"192.168.1.5", "192.168.1.5", true},
		{"192.168.1.5", "192.168.1.6", false},
		{"192.168.1.0/24", "192.168.1.5", true},
		{"192.168.1.0/24", "192.168.2.5", false},
		{"10.0.0.0/8", "10.254.0.1", true},
		{"2001:db8::/32", "2001:db8::1", true},
		{"2001:db8::/32", "2001:db9::1", false},
	}

	for _, tc := range tests {
		res := matchIP(tc.ruleIP, tc.packetIP)
		if res != tc.expected {
			t.Errorf("matchIP(%q, %q) = %v; want %v", tc.ruleIP, tc.packetIP, res, tc.expected)
		}
	}
}

func TestMatchPort(t *testing.T) {
	tests := []struct {
		rulePort      int
		rulePortRange string
		packetPort    int
		expected      bool
	}{
		{0, "", 80, true},
		{80, "", 80, true},
		{80, "", 443, false},
		{0, "80,443,8080", 443, true},
		{0, "80,443,8080", 8080, true},
		{0, "80,443,8080", 22, false},
		{0, "1000-2000", 1500, true},
		{0, "1000-2000", 1000, true},
		{0, "1000-2000", 2000, true},
		{0, "1000-2000", 999, false},
		{0, "1000-2000", 2001, false},
	}

	for _, tc := range tests {
		res := matchPort(tc.rulePort, tc.rulePortRange, tc.packetPort)
		if res != tc.expected {
			t.Errorf("matchPort(%d, %q, %d) = %v; want %v", tc.rulePort, tc.rulePortRange, tc.packetPort, res, tc.expected)
		}
	}
}

func TestRegexMatch(t *testing.T) {
	engine := NewRuleEngine()
	rulesYaml := `
rules:
  - id: "regex-test"
    name: "Regex Test Rule"
    protocol: "TCP"
    payload_regex: "(?i)malicious.*string"
    action: "BLOCK"
    duration: 60
`
	tmpDir, err := os.MkdirTemp("", "rule_engine_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulePath := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulePath, []byte(rulesYaml), 0644); err != nil {
		t.Fatalf("failed to write temp rules file: %v", err)
	}

	if err := engine.LoadRules(rulePath); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	p1 := &proto.PacketReport{
		Protocol:    "TCP",
		PayloadPeek: []byte("Some MALICIOUS payload STRING here"),
	}
	if _, matched := engine.Evaluate(p1); !matched {
		t.Errorf("expected packet 1 to match regex rule")
	}

	p2 := &proto.PacketReport{
		Protocol:    "TCP",
		PayloadPeek: []byte("Some benign string"),
	}
	if _, matched := engine.Evaluate(p2); matched {
		t.Errorf("expected packet 2 to NOT match regex rule")
	}
}

func TestDynamicReload(t *testing.T) {
	engine := NewRuleEngine()
	
	rulesYaml1 := `
rules:
  - id: "rule1"
    name: "Rule 1"
    protocol: "TCP"
    action: "BLOCK"
`
	tmpDir, err := os.MkdirTemp("", "rule_engine_test_dynamic")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	rulePath := filepath.Join(tmpDir, "rules.yaml")
	if err := os.WriteFile(rulePath, []byte(rulesYaml1), 0644); err != nil {
		t.Fatalf("failed to write temp rules file: %v", err)
	}

	if err := engine.LoadRules(rulePath); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	p := &proto.PacketReport{Protocol: "TCP"}
	if _, matched := engine.Evaluate(p); !matched {
		t.Errorf("expected rule 1 to match initially")
	}

	rulesYaml2 := `
rules:
  - id: "rule2"
    name: "Rule 2"
    protocol: "UDP"
    action: "BLOCK"
`
	time.Sleep(1 * time.Second)
	if err := os.WriteFile(rulePath, []byte(rulesYaml2), 0644); err != nil {
		t.Fatalf("failed to update temp rules file: %v", err)
	}

	// Wait for the watcher to trigger and complete reload (runs every 2 seconds)
	time.Sleep(2500 * time.Millisecond)

	pTCP := &proto.PacketReport{Protocol: "TCP"}
	pUDP := &proto.PacketReport{Protocol: "UDP"}

	if _, matched := engine.Evaluate(pTCP); matched {
		t.Errorf("expected TCP rule to not match after reload")
	}
	if _, matched := engine.Evaluate(pUDP); !matched {
		t.Errorf("expected UDP rule to match after reload")
	}
}
