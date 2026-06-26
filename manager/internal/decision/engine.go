package decision

import (
	"fmt"
	"log"
	"sync"

	"snffr/manager/internal/ai"
	"snffr/manager/internal/rules"
)

// ─────────────────────────────────────────────────────────────────────────────
// Decision type
// ─────────────────────────────────────────────────────────────────────────────

// Decision represents the enforcement action to apply to a network flow.
type Decision int

const (
	// Allow permits the flow to pass without restriction.
	Allow Decision = iota

	// RateLimit throttles the flow to reduce its impact.
	RateLimit

	// Block drops the flow entirely.
	Block
)

// String returns a human-readable label for the Decision value.
func (d Decision) String() string {
	switch d {
	case Allow:
		return "ALLOW"
	case RateLimit:
		return "RATE_LIMIT"
	case Block:
		return "BLOCK"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(d))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk thresholds
// ─────────────────────────────────────────────────────────────────────────────

const (
	// thresholdRateLimit is the minimum total risk score that triggers RATE_LIMIT.
	thresholdRateLimit = 30

	// thresholdBlock is the minimum total risk score that triggers BLOCK.
	thresholdBlock = 60
)

// ─────────────────────────────────────────────────────────────────────────────
// Engine — singleton orchestrator
// ─────────────────────────────────────────────────────────────────────────────

// Engine orchestrates AI inference and rule evaluation to produce a Decision.
//
// Create an Engine with NewEngine and call EvaluateFlow for each network flow.
// Engine is safe for concurrent use.
type Engine struct {
	predictor *ai.Predictor
	rules     *rules.Engine
}

// NewEngine constructs a fully initialised Engine using the ONNX model at
// modelPath and the default built-in rule set.
//
// modelPath should be relative to the process working directory or an absolute
// path (e.g. "models/ids_model.onnx").
func NewEngine(modelPath string) (*Engine, error) {
	predictor, err := ai.NewPredictor(modelPath)
	if err != nil {
		return nil, fmt.Errorf("decision: failed to initialise AI predictor: %w", err)
	}

	return &Engine{
		predictor: predictor,
		rules:     rules.NewEngine(),
	}, nil
}

// NewEngineWithComponents constructs an Engine with externally supplied
// components.  This is the recommended constructor for tests and for
// deployments that need a custom rule set or a mock predictor.
func NewEngineWithComponents(predictor *ai.Predictor, ruleEngine *rules.Engine) *Engine {
	return &Engine{
		predictor: predictor,
		rules:     ruleEngine,
	}
}

// Close releases resources held by the underlying AI Predictor.
// It is safe to call Close more than once.
func (e *Engine) Close() {
	if e.predictor != nil {
		e.predictor.Close()
	}
}

// EvaluateFlow runs the full inference + rule pipeline for flow and returns:
//   - decision: the enforcement action (Allow / RateLimit / Block)
//   - totalRisk: the summed risk score (aiRisk + ruleRisk)
//   - err: non-nil if ONNX inference failed (rule score is still returned)
//
// EvaluateFlow is safe for concurrent use.
func (e *Engine) EvaluateFlow(flow ai.FlowFeatures) (Decision, int, error) {
	// ── 1. AI inference ───────────────────────────────────────────────────────
	aiRisk, err := e.predictor.Predict(flow)
	if err != nil {
		// Log the error but continue with rule-only evaluation so we never
		// silently drop a potentially malicious flow due to an inference glitch.
		log.Printf("[decision] AI inference error: %v — using aiRisk=0", err)
	}

	// ── 2. Rule evaluation ────────────────────────────────────────────────────
	ruleRisk := e.rules.Score(flow)

	// ── 3. Risk fusion ────────────────────────────────────────────────────────
	totalRisk := aiRisk + ruleRisk

	// ── 4. Threshold mapping ──────────────────────────────────────────────────
	d := classify(totalRisk)

	return d, totalRisk, err
}

// classify maps a numeric risk score to a Decision.
func classify(risk int) Decision {
	switch {
	case risk >= thresholdBlock:
		return Block
	case risk >= thresholdRateLimit:
		return RateLimit
	default:
		return Allow
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Package-level singleton (optional convenience API)
// ─────────────────────────────────────────────────────────────────────────────

var (
	globalOnce   sync.Once
	globalEngine *Engine
	globalErr    error
)

// Init initialises the package-level singleton Engine.
// It must be called once before EvaluateFlow.
// Subsequent calls are no-ops (idempotent).
func Init(modelPath string) error {
	globalOnce.Do(func() {
		globalEngine, globalErr = NewEngine(modelPath)
	})
	return globalErr
}

// EvaluateFlow evaluates a flow using the package-level singleton Engine.
//
// Init must be called successfully before EvaluateFlow.
func EvaluateFlow(flow ai.FlowFeatures) (Decision, int, error) {
	if globalEngine == nil {
		return Allow, 0, fmt.Errorf("decision: package not initialised — call decision.Init first")
	}
	return globalEngine.EvaluateFlow(flow)
}
