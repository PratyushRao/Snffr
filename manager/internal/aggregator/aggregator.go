package aggregator

import (
	"fmt"
	"log"
	"sync"
	"time"

	"snffr/manager/internal/ai"
	"snffr/manager/proto"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tunable constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	// windowDuration is the time a flow is allowed to accumulate packets before
	// it is exported and evaluated. Shorter windows catch bursts faster;
	// longer windows give the model more signal per evaluation.
	windowDuration = 5 * time.Second

	// minPackets is the minimum number of packets a flow must have seen before
	// it is eligible for export at the end of a time window.
	// This prevents single-packet flows from generating noisy decisions.
	minPackets = 3

	// maxPackets forces an early export when a flow reaches this packet count,
	// regardless of the time window. Prevents memory growth from very high-rate
	// flows and ensures the AI sees high-volume attacks quickly.
	maxPackets = 200
)

// ─────────────────────────────────────────────────────────────────────────────
// FlowKey — uniquely identifies one directional network flow
// ─────────────────────────────────────────────────────────────────────────────

// FlowKey identifies a unique directional flow by its 4-tuple.
// We use source IP + destination IP + destination port + protocol because this
// mirrors what the IDS model was trained on and matches iptables/netsh semantics
// for the mitigation commands the agent executes.
type FlowKey struct {
	SrcIP    string
	DstIP    string
	DstPort  uint32
	Protocol string
}

// String returns a human-readable representation of the flow key for logging.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s → %s:%d/%s", k.SrcIP, k.DstIP, k.DstPort, k.Protocol)
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowState — mutable counters for one active flow
// ─────────────────────────────────────────────────────────────────────────────

// flowState holds per-flow counters accumulated from individual PacketReports.
// All fields are protected by the Aggregator's mutex.
type flowState struct {
	firstSeen    time.Time // timestamp of the first packet in this window
	lastSeen     time.Time // timestamp of the most recent packet
	totalPackets int       // total packets seen (forward + reverse)
	totalBytes   int       // total bytes across all packets
	fwdPackets   int       // packets in the forward direction (src→dst)
	fwdBytes     int       // bytes in the forward direction
	dstPort      uint32    // cached for FlowFeatures assembly
}

// toFeatures converts the accumulated counters into the FlowFeatures vector
// that the ONNX model expects. Called at export time.
func (s *flowState) toFeatures() ai.FlowFeatures {
	durationSec := s.lastSeen.Sub(s.firstSeen).Seconds()
	if durationSec <= 0 {
		// Guard against zero-duration (all packets at the same timestamp).
		// Use a 1 ms floor so bytes/s and packets/s remain finite.
		durationSec = 0.001
	}

	avgPktSize := float32(0)
	if s.totalPackets > 0 {
		avgPktSize = float32(s.totalBytes) / float32(s.totalPackets)
	}

	return ai.FlowFeatures{
		// Feature 1: destination port
		DestinationPort: float32(s.dstPort),

		// Feature 2: flow duration in microseconds (matches training data units)
		FlowDuration: float32(s.lastSeen.Sub(s.firstSeen).Microseconds()),

		// Feature 3 & 4: forward packet count and total forward byte length
		TotalFwdPackets:       float32(s.fwdPackets),
		TotalLengthFwdPackets: float32(s.fwdBytes),

		// Feature 5 & 6: derived rates over the full flow duration
		FlowBytesPerSecond:   float32(float64(s.totalBytes) / durationSec),
		FlowPacketsPerSecond: float32(float64(s.totalPackets) / durationSec),

		// Feature 7: mean packet size
		AveragePacketSize: avgPktSize,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowResult — what the aggregator returns when a flow is ready
// ─────────────────────────────────────────────────────────────────────────────

// FlowResult is returned by Ingest when a flow window is complete and ready
// for AI evaluation.
type FlowResult struct {
	// Key is the flow that triggered the export.
	Key FlowKey

	// SrcIP is a convenience copy of Key.SrcIP used when building ActionCommands.
	SrcIP string

	// Features is the assembled FlowFeatures vector for the ONNX model.
	Features ai.FlowFeatures

	// PacketCount is how many packets were in the exported window (for logging).
	PacketCount int
}

// ─────────────────────────────────────────────────────────────────────────────
// Aggregator
// ─────────────────────────────────────────────────────────────────────────────

// Aggregator is a stateful, thread-safe component that groups per-packet
// PacketReports into per-flow windows and emits a FlowResult when a window
// is complete.
//
// Create one with NewAggregator and call Ingest for every incoming PacketReport.
// When Ingest returns a non-nil *FlowResult the caller should evaluate it with
// decision.EvaluateFlow and act on the outcome.
//
// A background goroutine sweeps for flows whose time window has expired but
// that have not yet seen a new packet (quiescent flows). This ensures every
// flow eventually gets evaluated even if traffic stops mid-window.
type Aggregator struct {
	mu    sync.Mutex
	flows map[FlowKey]*flowState

	// results is an internal channel on which the sweep goroutine pushes
	// expired quiescent flows. Callers drain it via Results().
	results chan *FlowResult

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewAggregator creates and starts an Aggregator. Call Close when done.
func NewAggregator() *Aggregator {
	a := &Aggregator{
		flows:   make(map[FlowKey]*flowState),
		results: make(chan *FlowResult, 256),
		stopCh:  make(chan struct{}),
	}

	// Start the background sweep goroutine.
	a.wg.Add(1)
	go a.sweepLoop()

	return a
}

// Ingest processes one PacketReport. It updates the matching flow's counters
// and, if the flow is ready for evaluation (packet-count threshold reached),
// immediately returns a *FlowResult.
//
// For time-window expiry the caller should also drain the Results() channel,
// which is written to by the background sweep goroutine.
//
// Returns nil when the flow window is not yet complete.
//
// Ingest is safe for concurrent use from multiple goroutines (e.g. one per
// connected agent stream).
func (a *Aggregator) Ingest(report *proto.PacketReport) *FlowResult {
	key := FlowKey{
		SrcIP:    report.SrcIp,
		DstIP:    report.DstIp,
		DstPort:  report.DstPort,
		Protocol: report.Protocol,
	}

	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	state, exists := a.flows[key]
	if !exists {
		state = &flowState{
			firstSeen: now,
			dstPort:   report.DstPort,
		}
		a.flows[key] = state
	}

	// Accumulate counters.
	state.lastSeen = now
	state.totalPackets++
	state.totalBytes += int(report.Length)

	// All packets from src→dst are treated as forward direction.
	state.fwdPackets++
	state.fwdBytes += int(report.Length)

	// Check whether we should force-export due to packet count.
	if state.totalPackets >= maxPackets {
		return a.exportLocked(key, state)
	}

	return nil
}

// Results returns a read-only channel that delivers FlowResults from quiescent
// flows whose time window was closed by the background sweep goroutine.
//
// The caller must read from this channel continuously to avoid blocking the sweep.
func (a *Aggregator) Results() <-chan *FlowResult {
	return a.results
}

// Close stops the background sweep goroutine and releases resources.
// It is safe to call Close more than once.
func (a *Aggregator) Close() {
	select {
	case <-a.stopCh:
		// already closed
	default:
		close(a.stopCh)
	}
	a.wg.Wait()
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// exportLocked exports a flow and removes it from the active map. Must be called
// with a.mu held.
func (a *Aggregator) exportLocked(key FlowKey, state *flowState) *FlowResult {
	result := &FlowResult{
		Key:         key,
		SrcIP:       key.SrcIP,
		Features:    state.toFeatures(),
		PacketCount: state.totalPackets,
	}
	delete(a.flows, key)
	return result
}

// sweepLoop runs in a goroutine and periodically exports flows whose time window
// has elapsed but that have not received a new packet (so Ingest was never
// called to trigger the packet-count path).
func (a *Aggregator) sweepLoop() {
	defer a.wg.Done()

	// Sweep every half-window so we don't let flows expire more than 2.5 s late.
	ticker := time.NewTicker(windowDuration / 2)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			return
		case now := <-ticker.C:
			a.sweep(now)
		}
	}
}

// sweep scans all active flows and exports those whose window has expired and
// that have accumulated at least minPackets.
func (a *Aggregator) sweep(now time.Time) {
	a.mu.Lock()
	var ready []*FlowResult
	for key, state := range a.flows {
		windowExpired := now.Sub(state.firstSeen) >= windowDuration
		enoughPackets := state.totalPackets >= minPackets
		if windowExpired && enoughPackets {
			ready = append(ready, a.exportLocked(key, state))
		} else if windowExpired && !enoughPackets {
			// Too few packets to be meaningful — discard silently and reset.
			log.Printf("[aggregator] discarding thin flow %s (%d pkts, window expired)",
				key, state.totalPackets)
			delete(a.flows, key)
		}
	}
	a.mu.Unlock()

	// Push results outside the lock so we don't block Ingest callers.
	for _, r := range ready {
		select {
		case a.results <- r:
		default:
			// Channel full — log and drop rather than deadlock.
			log.Printf("[aggregator] results channel full, dropping flow result for %s", r.Key)
		}
	}
}
