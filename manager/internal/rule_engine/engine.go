package rule_engine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"snffr/manager/proto"

	"github.com/goccy/go-yaml"
)

type Threshold struct {
	Packets       int `yaml:"packets"`
	WindowSeconds int `yaml:"window_seconds"`
}

type Rule struct {
	ID            string     `yaml:"id"`
	Name          string     `yaml:"name"`
	Protocol      string     `yaml:"protocol,omitempty"`
	SrcIP         string     `yaml:"src_ip,omitempty"`
	DstIP         string     `yaml:"dst_ip,omitempty"`
	SrcPort       int        `yaml:"src_port,omitempty"`
	DstPort       int        `yaml:"dst_port,omitempty"`
	PayloadHex    string     `yaml:"payload_hex,omitempty"`
	PayloadString string     `yaml:"payload_string,omitempty"`
	Action        string     `yaml:"action"` // BLOCK, RATE_LIMIT, ALLOW
	Duration      uint32     `yaml:"duration"`
	RateLimitPPS  uint32     `yaml:"rate_limit_pps"`
	Reason        string     `yaml:"reason"`
	Threshold     *Threshold `yaml:"threshold,omitempty"`
}

type RuleEngine struct {
	rules []Rule
	mu    sync.Mutex
	// stateful tracking: ruleID -> srcIP -> list of packet timestamps
	history map[string]map[string][]time.Time
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:   make([]Rule, 0),
		history: make(map[string]map[string][]time.Time),
	}
}

func (re *RuleEngine) LoadRules(path string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	var config struct {
		Rules []Rule `yaml:"rules"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal rules YAML: %w", err)
	}

	re.rules = config.Rules
	log.Printf("[Rule Engine] Loaded %d rules successfully from %s\n", len(re.rules), path)
	for _, r := range re.rules {
		log.Printf(" - [%s] %s (Action: %s)\n", r.ID, r.Name, r.Action)
	}

	// reset stateful history on reload
	re.history = make(map[string]map[string][]time.Time)

	return nil
}

// Match a given report to the rule criteria
func (r *Rule) Match(report *proto.PacketReport) bool {
	// If [___] is specified -> check if the report matches the rule criteria
	if r.Protocol != "" && !strings.EqualFold(report.Protocol, r.Protocol) {
		return false
	}
	if r.SrcIP != "" && report.SrcIp != r.SrcIP {
		return false
	}
	if r.DstIP != "" && report.DstIp != r.DstIP {
		return false
	}
	if r.SrcPort != 0 && int(report.SrcPort) != r.SrcPort {
		return false
	}
	if r.DstPort != 0 && int(report.DstPort) != r.DstPort {
		return false
	}

	// If [___] is specified -> check if a peek contains it
	if r.PayloadHex != "" {
		hexBytes, err := hex.DecodeString(r.PayloadHex)
		if err != nil {
			return false
		}
		if !bytes.Contains(report.PayloadPeek, hexBytes) {
			return false
		}
	}
	if r.PayloadString != "" {
		if !bytes.Contains(report.PayloadPeek, []byte(r.PayloadString)) {
			return false
		}
	}
	return true
}

// Evaluate a report against all loaded rules
func (re *RuleEngine) Evaluate(report *proto.PacketReport) (*proto.ActionCommand, bool) {
	re.mu.Lock()
	defer re.mu.Unlock()

	for _, rule := range re.rules {
		if !rule.Match(report) {
			continue
		}

		// Check stateful threshold if specified
		if rule.Threshold != nil {
			if rule.Threshold.Packets <= 0 || rule.Threshold.WindowSeconds <= 0 {
				continue
			}

			srcIP := report.SrcIp
			ruleID := rule.ID

			if re.history[ruleID] == nil {
				re.history[ruleID] = make(map[string][]time.Time)
			}

			now := time.Now()
			// Append current packet timestamp
			re.history[ruleID][srcIP] = append(re.history[ruleID][srcIP], now)

			// Clear up old timestamps
			cutoff := now.Add(-time.Duration(rule.Threshold.WindowSeconds) * time.Second)
			validTimes := make([]time.Time, 0, len(re.history[ruleID][srcIP]))
			for _, t := range re.history[ruleID][srcIP] {
				if t.After(cutoff) {
					validTimes = append(validTimes, t)
				}
			}
			re.history[ruleID][srcIP] = validTimes

			// If threshold exceeded -> trigger some action
			if len(validTimes) >= rule.Threshold.Packets {
				// Clear history for this IP to prevent consecutive triggers
				re.history[ruleID][srcIP] = nil

				actionType := proto.ActionCommand_BLOCK
				switch strings.ToUpper(rule.Action) {
				case "RATE_LIMIT":
					actionType = proto.ActionCommand_RATE_LIMIT
				case "ALLOW":
					actionType = proto.ActionCommand_ALLOW
				}

				reason := fmt.Sprintf("%s (Triggered by threshold: %d packets in %ds)",
					rule.Reason, rule.Threshold.Packets, rule.Threshold.WindowSeconds)

				return &proto.ActionCommand{
					Action:          actionType,
					TargetIp:        srcIP,
					Reason:          reason,
					DurationSeconds: rule.Duration,
					RateLimitPps:    rule.RateLimitPPS,
				}, true
			}
		} else {
			// Stateless signatures -> we ball (do thing immediatelty)
			actionType := proto.ActionCommand_BLOCK
			switch strings.ToUpper(rule.Action) {
			case "RATE_LIMIT":
				actionType = proto.ActionCommand_RATE_LIMIT
			case "ALLOW":
				actionType = proto.ActionCommand_ALLOW
			}

			return &proto.ActionCommand{
				Action:          actionType,
				TargetIp:        report.SrcIp,
				Reason:          rule.Reason,
				DurationSeconds: rule.Duration,
				RateLimitPps:    rule.RateLimitPPS,
			}, true
		}
	}

	return nil, false
}
