//go:build linux

package ai

import (
	"context"
	"fmt"
	"sync"

	"github.com/shota3506/onnxruntime-purego/onnxruntime"
)

const (
	// onnxAPIVersion is the ONNX Runtime C API version this package targets.
	// The system DLL (onnxruntime.dll / libonnxruntime.so) must be >= this version.
	onnxAPIVersion uint32 = 23

	// modelInputName is the name of the model's input node as exported from sklearn.
	modelInputName = "X"

	// modelOutputLabel is the name of the model's classification label output.
	// IsolationForest emits 1 (normal) or -1 (anomaly).
	modelOutputLabel = "label"
)

// Predictor wraps an ONNX Runtime session for IsolationForest inference.
//
// It loads the model once at construction time and reuses the same session
// for every call to Predict. The session is created with the model's embedded
// StandardScaler so callers must feed raw (unscaled) feature values.
//
// Predictor is safe for concurrent use: each Predict call allocates its own
// input/output tensors and the underlying ONNX Runtime session is thread-safe
// for concurrent Run() invocations.
type Predictor struct {
	// mu guards the session against concurrent Close calls. Individual Run()
	// calls are thread-safe in ONNX Runtime itself.
	mu sync.RWMutex

	// runtime is the loaded ONNX Runtime shared library handle.
	runtime *onnxruntime.Runtime

	// env is the ONNX Runtime environment (global logging / threading state).
	env *onnxruntime.Env

	// session is the reusable inference session for ids_model.onnx.
	session *onnxruntime.Session

	// modelPath is retained so callers can inspect which model is loaded.
	modelPath string

	// closed is true after Close() has been called.
	closed bool
}

// NewPredictor loads the ONNX model at modelPath and initialises a reusable
// inference session. The caller is responsible for calling Close() when the
// Predictor is no longer needed.
//
// modelPath must point to a valid sklearn-exported ONNX pipeline that accepts
// a single input named "X" of shape [batch, 7] and returns at least a "label"
// output of type int64.
//
// The ONNX Runtime shared library is loaded from the standard system location
// (libonnxruntime.so on Linux, onnxruntime.dll on Windows). Set the
// SNFFR_ONNX_LIB environment variable — or pass a custom wrapper — to
// override the library path at a higher level.
func NewPredictor(modelPath string) (*Predictor, error) {
	// Load the ONNX Runtime shared library.
	// Passing an empty string tells the library to search standard system paths,
	// which is the correct behaviour inside the Docker container.
	rt, err := onnxruntime.NewRuntime("", onnxAPIVersion)
	if err != nil {
		return nil, fmt.Errorf("ai: failed to load ONNX Runtime library: %w", err)
	}

	// Create the global environment (manages thread pool, logging).
	env, err := rt.NewEnv("snffr-ids", onnxruntime.LoggingLevelWarning)
	if err != nil {
		rt.Close()
		return nil, fmt.Errorf("ai: failed to create ONNX Runtime environment: %w", err)
	}

	// Create the inference session from the model file.
	// Session creation validates that the model is readable and well-formed.
	session, err := rt.NewSession(env, modelPath, nil)
	if err != nil {
		env.Close()
		rt.Close()
		return nil, fmt.Errorf("ai: failed to create ONNX session from %q: %w", modelPath, err)
	}

	return &Predictor{
		runtime:   rt,
		env:       env,
		session:   session,
		modelPath: modelPath,
	}, nil
}

// Close releases all ONNX Runtime resources held by the Predictor.
// It is safe to call Close more than once; subsequent calls are no-ops.
func (p *Predictor) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	if p.session != nil {
		p.session.Close()
		p.session = nil
	}
	if p.env != nil {
		p.env.Close()
		p.env = nil
	}
	if p.runtime != nil {
		p.runtime.Close()
		p.runtime = nil
	}
}

// ModelPath returns the path of the ONNX model file that was loaded.
func (p *Predictor) ModelPath() string {
	return p.modelPath
}

// Predict runs inference on the given FlowFeatures and returns an AI risk score.
//
// The returned risk score is:
//   - 0  — the model classified the flow as NORMAL  (IsolationForest label == 1)
//   - 50 — the model classified the flow as ANOMALOUS (IsolationForest label == -1)
//
// Predict is safe to call from multiple goroutines simultaneously.
func (p *Predictor) Predict(f FlowFeatures) (int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return 0, fmt.Errorf("ai: Predictor has been closed")
	}

	// Build the input tensor: shape [1, 7], dtype float32.
	featureVec := ToFeatureVector(f)
	inputVal, err := onnxruntime.NewTensorValue(p.runtime, featureVec, []int64{1, numFeatures})
	if err != nil {
		return 0, fmt.Errorf("ai: failed to create input tensor: %w", err)
	}
	defer inputVal.Close()

	// Run inference. The session returns a map of output name → *Value.
	outputs, err := p.session.Run(
		context.Background(),
		map[string]*onnxruntime.Value{modelInputName: inputVal},
	)
	if err != nil {
		return 0, fmt.Errorf("ai: ONNX session Run failed: %w", err)
	}
	defer func() {
		for _, v := range outputs {
			v.Close()
		}
	}()

	// Extract the classification label.
	labelVal, ok := outputs[modelOutputLabel]
	if !ok {
		return 0, fmt.Errorf("ai: model output %q not found in results", modelOutputLabel)
	}

	labels, _, err := onnxruntime.GetTensorData[int64](labelVal)
	if err != nil {
		return 0, fmt.Errorf("ai: failed to decode label tensor: %w", err)
	}
	if len(labels) == 0 {
		return 0, fmt.Errorf("ai: label tensor is empty")
	}

	return mapLabelToRisk(labels[0]), nil
}
