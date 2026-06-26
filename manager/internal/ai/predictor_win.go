//go:build windows

// Package ai — Windows stub.
//
// On Windows the real ONNX Runtime predictor is not available because 
// onnxruntime-purego only supports Linux in this build.
// This stub satisfies the compiler so that tests that do not exercise ONNX
// inference (rules, decision, features) can be built and run locally on Windows.
//
// In production the service is always built and run inside the Linux Docker
// container, where predictor.go (//go:build linux) is used instead.
package ai

import "fmt"

// Predictor is a placeholder on Windows.
type Predictor struct {
	modelPath string
	closed    bool
}

// NewPredictor returns an error on Windows platforms.
func NewPredictor(modelPath string) (*Predictor, error) {
	return nil, fmt.Errorf("ai: ONNX Runtime is only supported on Linux (current platform: windows)")
}

// Close is a no-op on Windows.
func (p *Predictor) Close() {}

// ModelPath returns the model path string.
func (p *Predictor) ModelPath() string { return p.modelPath }

// Predict always returns an error on Windows.
func (p *Predictor) Predict(_ FlowFeatures) (int, error) {
	return 0, fmt.Errorf("ai: ONNX Runtime is only supported on Linux")
}
