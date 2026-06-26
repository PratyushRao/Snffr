package rule_engine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
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
	ID            string         `yaml:"id"`
	Name          string         `yaml:"name"`
	Protocol      string         `yaml:"protocol,omitempty"`
	SrcIP         string         `yaml:"src_ip,omitempty"`
	DstIP         string         `yaml:"dst_ip,omitempty"`
	SrcPort       int            `yaml:"src_port,omitempty"`
	DstPort       int            `yaml:"dst_port,omitempty"`
	SrcPortRange  string         `yaml:"src_port_range,omitempty"`
	DstPortRange  string         `yaml:"dst_port_range,omitempty"`
	PayloadHex    string         `yaml:"payload_hex,omitempty"`
	PayloadString string         `yaml:"payload_string,omitempty"`
	PayloadRegex  string         `yaml:"payload_regex,omitempty"`
	compiledRegex *regexp.Regexp // Unexported, compiled during LoadRules
	Action        string         `yaml:"action"` // BLOCK, RATE_LIMIT, ALLOW
	Duration      uint32         `yaml:"duration"`
	RateLimitPPS  uint32         `yaml:"rate_limit_pps"`
	Reason        string         `yaml:"reason"`
	Threshold     *Threshold     `yaml:"threshold,omitempty"`
}

type RuleEngine struct {
	rules    []Rule
	mu       sync.Mutex
	watching bool
	// stateful tracking: ruleID -> srcIP -> list of packet timestamps
	history map[string]map[string][]time.Time
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:   make([]Rule, 0),
		history: make(map[string]map[string][]time.Time),
	}
}

func (re *RuleEngine) watchRules(path string) {
	go func() {
		var lastModTime time.Time
		if info, err := os.Stat(path); err == nil {
			lastModTime = info.ModTime()
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			if info.ModTime().After(lastModTime) {
				log.Printf("[Rule Engine] Rules file modification detected. Reloading rules...")
				if err := re.LoadRules(path); err != nil {
					log.Printf("[Rule Engine] Error reloading rules: %v\n", err)
				} else {
					lastModTime = info.ModTime()
				}
			}
		}
	}()
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

	// Compile regex for rules
	for i := range config.Rules {
		if config.Rules[i].PayloadRegex != "" {
			r, err := regexp.Compile(config.Rules[i].PayloadRegex)
			if err != nil {
				return fmt.Errorf("failed to compile regex for rule %s: %w", config.Rules[i].ID, err)
			}
			config.Rules[i].compiledRegex = r
		}
	}

	re.rules = config.Rules
	log.Printf("[Rule Engine] Loaded %d rules successfully from %s\n", len(re.rules), path)
	for _, r := range re.rules {
		log.Printf(" - [%s] %s (Action: %s)\n", r.ID, r.Name, r.Action)
	}

	// reset stateful history on reload
	re.history = make(map[string]map[string][]time.Time)

	// If not watching yet, start watching rules file
	if !re.watching {
		re.watching = true
		re.watchRules(path)
	}

	return nil
}

func matchIP(ruleIP, packetIP string) bool {
	if ruleIP == "" {
		return true
	}
	if packetIP == "" {
		return false
	}

	// Check if ruleIP is a CIDR block
	if strings.Contains(ruleIP, "/") {
		_, ipnet, err := net.ParseCIDR(ruleIP)
		if err == nil {
			parsedPacketIP := net.ParseIP(packetIP)
			if parsedPacketIP != nil && ipnet.Contains(parsedPacketIP) {
				return true
			}
			return false
		}
	}

	// Direct IP check
	rIP := net.ParseIP(ruleIP)
	pIP := net.ParseIP(packetIP)
	if rIP != nil && pIP != nil {
		return rIP.Equal(pIP)
	}

	return ruleIP == packetIP
}

func matchPort(rulePort int, rulePortRange string, packetPort int) bool {
	if rulePort == 0 && rulePortRange == "" {
		return true
	}

	if rulePort != 0 {
		return packetPort == rulePort
	}

	if rulePortRange != "" {
		// list of ports: e.g. "80,443"
		if strings.Contains(rulePortRange, ",") {
			parts := strings.Split(rulePortRange, ",")
			for _, part := range parts {
				p, err := strconv.Atoi(strings.TrimSpace(part))
				if err == nil && p == packetPort {
					return true
				}
			}
			return false
		}

		// port range: e.g. "1000-2000"
		if strings.Contains(rulePortRange, "-") {
			parts := strings.Split(rulePortRange, "-")
			if len(parts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err1 == nil && err2 == nil {
					return packetPort >= start && packetPort <= end
				}
			}
			return false
		}

		p, err := strconv.Atoi(strings.TrimSpace(rulePortRange))
		if err == nil {
			return p == packetPort
		}
	}

	return false
}

// match a report to the rule criteria
func (r *Rule) Match(report *proto.PacketReport) bool {
	if r.Protocol != "" && !strings.EqualFold(report.Protocol, r.Protocol) {
		return false
	}
	if !matchIP(r.SrcIP, report.SrcIp) {
		return false
	}
	if !matchIP(r.DstIP, report.DstIp) {
		return false
	}
	if !matchPort(r.SrcPort, r.SrcPortRange, int(report.SrcPort)) {
		return false
	}
	if !matchPort(r.DstPort, r.DstPortRange, int(report.DstPort)) {
		return false
	}

	// check payload matches
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
	if r.compiledRegex != nil {
		if !r.compiledRegex.Match(report.PayloadPeek) {
			return false
		}
	}
	return true
}

// evaluate a report against all loaded rules
func (re *RuleEngine) Evaluate(report *proto.PacketReport) (*proto.ActionCommand, bool) {
	re.mu.Lock()
	defer re.mu.Unlock()

	for _, rule := range re.rules {
		if !rule.Match(report) {
			continue
		}

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

			// clear up old timestamps
			cutoff := now.Add(-time.Duration(rule.Threshold.WindowSeconds) * time.Second)
			validTimes := make([]time.Time, 0, len(re.history[ruleID][srcIP]))
			for _, t := range re.history[ruleID][srcIP] {
				if t.After(cutoff) {
					validTimes = append(validTimes, t)
				}
			}
			re.history[ruleID][srcIP] = validTimes

			// if threshold exceeded -> trigger some action
			if len(validTimes) >= rule.Threshold.Packets {
				// clear history for this IP to prevent consecutive triggers
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
