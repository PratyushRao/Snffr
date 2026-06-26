package rules

import "snffr/manager/internal/ai"

// ─────────────────────────────────────────────────────────────────────────────
// Threshold constants
//
// These values define "suspicious" levels for each feature.  They can be tuned
// without touching rule logic; change a constant, recompile, redeploy.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// thresholdFlowBytesPerSecond is the bytes/s above which a flow is considered
	// to be generating very high throughput (e.g. DDoS flood, large exfiltration).
	thresholdFlowBytesPerSecond float32 = 1_000_000 // 1 MB/s

	// thresholdFlowPacketsPerSecond is the packet-rate above which a flow is
	// considered to be a high-rate attack (e.g. SYN flood, UDP amplification).
	thresholdFlowPacketsPerSecond float32 = 1_000 // 1 k pps

	// thresholdTotalFwdPackets is the forward packet count above which a flow is
	// unusually large (e.g. long-lived scanning or exfiltration session).
	thresholdTotalFwdPackets float32 = 500

	// thresholdAveragePacketSize is the mean packet size (bytes) above which
	// packets are considered very large (e.g. jumbo-frame abuse, bulk transfer).
	thresholdAveragePacketSize float32 = 1_400 // close to typical MTU

	// ─── Risk deltas ───────────────────────────────────────────────────────────

	// riskHighFlowBytes is added when FlowBytesPerSecond exceeds its threshold.
	riskHighFlowBytes = 20

	// riskHighFlowPackets is added when FlowPacketsPerSecond exceeds its threshold.
	riskHighFlowPackets = 20

	// riskHighTotalFwdPackets is added when TotalFwdPackets exceeds its threshold.
	riskHighTotalFwdPackets = 15

	// riskLargeAvgPacket is added when AveragePacketSize exceeds its threshold.
	riskLargeAvgPacket = 10
)

// ─────────────────────────────────────────────────────────────────────────────
// Rule type
// ─────────────────────────────────────────────────────────────────────────────

// Rule is a named predicate that assigns a risk delta to a FlowFeatures value.
type Rule struct {
	// Name is a human-readable identifier used in logs and metrics.
	Name string

	// RiskDelta is the non-negative integer added to the total risk score when
	// the rule matches.
	RiskDelta int

	// Match returns true when the rule condition is met for the given features.
	Match func(f ai.FlowFeatures) bool
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in rules
// ─────────────────────────────────────────────────────────────────────────────

// defaultRules is the ordered list of rules applied by Engine.Score.
// All rules are stateless and safe for concurrent evaluation.
var defaultRules = []Rule{
	{
		Name:      "HighFlowBytesPerSecond",
		RiskDelta: riskHighFlowBytes,
		Match: func(f ai.FlowFeatures) bool {
			return f.FlowBytesPerSecond > thresholdFlowBytesPerSecond
		},
	},
	{
		Name:      "HighFlowPacketsPerSecond",
		RiskDelta: riskHighFlowPackets,
		Match: func(f ai.FlowFeatures) bool {
			return f.FlowPacketsPerSecond > thresholdFlowPacketsPerSecond
		},
	},
	{
		Name:      "HighTotalFwdPackets",
		RiskDelta: riskHighTotalFwdPackets,
		Match: func(f ai.FlowFeatures) bool {
			return f.TotalFwdPackets > thresholdTotalFwdPackets
		},
	},
	{
		Name:      "LargeAveragePacketSize",
		RiskDelta: riskLargeAvgPacket,
		Match: func(f ai.FlowFeatures) bool {
			return f.AveragePacketSize > thresholdAveragePacketSize
		},
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

// Engine evaluates a set of rules against FlowFeatures and returns a total
// rule risk score.
//
// The zero value is not usable; create an Engine with NewEngine or
// NewEngineWithRules.
//
// Engine is safe for concurrent use: Score is a pure read-only operation.
type Engine struct {
	rules []Rule
}

// NewEngine returns an Engine loaded with the default built-in rule set.
func NewEngine() *Engine {
	// Copy the slice so callers cannot mutate the package-level default.
	r := make([]Rule, len(defaultRules))
	copy(r, defaultRules)
	return &Engine{rules: r}
}

// NewEngineWithRules returns an Engine that uses the provided rules instead of
// the defaults.  This is useful for testing or for deployments that need a
// fully custom rule set.
//
// The rules slice is copied; subsequent mutations by the caller have no effect.
func NewEngineWithRules(rules []Rule) *Engine {
	r := make([]Rule, len(rules))
	copy(r, rules)
	return &Engine{rules: r}
}

// Score evaluates all rules against f and returns the summed risk score.
//
// Each matching rule contributes its RiskDelta to the total.  A score of 0
// means no rules fired; higher scores indicate more suspicious traffic.
//
// Score is safe to call concurrently from multiple goroutines.
func (e *Engine) Score(f ai.FlowFeatures) int {
	total := 0
	for _, rule := range e.rules {
		if rule.Match(f) {
			total += rule.RiskDelta
		}
	}
	return total
}

// Rules returns a copy of the rule list held by this engine.
// Useful for introspection and logging.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}
