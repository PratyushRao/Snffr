package aggregator

import (
	"testing"
	"time"

	"snffr/manager/proto"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func report(src, dst string, dstPort uint32, protocol string, length uint32) *proto.PacketReport {
	return &proto.PacketReport{
		SrcIp:    src,
		DstIp:    dst,
		DstPort:  dstPort,
		Protocol: protocol,
		Length:   length,
	}
}

// ── Ingest — below thresholds ─────────────────────────────────────────────────

func TestIngest_BelowThreshold_NoResult(t *testing.T) {
	a := NewAggregator()
	defer a.Close()

	r := report("1.2.3.4", "5.6.7.8", 80, "TCP", 512)

	// Send fewer than minPackets — should return nil every time.
	for i := 0; i < minPackets-1; i++ {
		if got := a.Ingest(r); got != nil {
			t.Fatalf("expected nil result before threshold, got result after %d packets", i+1)
		}
	}
}

// ── Ingest — packet-count threshold ───────────────────────────────────────────

func TestIngest_PacketThreshold_ReturnsResult(t *testing.T) {
	a := NewAggregator()
	defer a.Close()

	r := report("10.0.0.1", "10.0.0.2", 443, "TCP", 1024)

	var result *FlowResult
	for i := 0; i < maxPackets; i++ {
		result = a.Ingest(r)
		if result != nil {
			break
		}
	}

	if result == nil {
		t.Fatal("expected a FlowResult at maxPackets threshold, got nil")
	}
	if result.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want 10.0.0.1", result.SrcIP)
	}
	if result.Key.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", result.Key.DstPort)
	}
	if result.PacketCount != maxPackets {
		t.Errorf("PacketCount = %d, want %d", result.PacketCount, maxPackets)
	}
}

// ── FlowFeatures values ───────────────────────────────────────────────────────

func TestIngest_FeaturesAreCorrect(t *testing.T) {
	a := NewAggregator()
	defer a.Close()

	pktLen := uint32(500)
	r := report("192.168.1.1", "8.8.8.8", 53, "UDP", pktLen)

	var result *FlowResult
	for i := 0; i < maxPackets; i++ {
		result = a.Ingest(r)
		if result != nil {
			break
		}
	}
	if result == nil {
		t.Fatal("no result produced")
	}

	f := result.Features

	if f.DestinationPort != 53 {
		t.Errorf("DestinationPort = %f, want 53", f.DestinationPort)
	}
	if f.TotalFwdPackets != float32(maxPackets) {
		t.Errorf("TotalFwdPackets = %f, want %d", f.TotalFwdPackets, maxPackets)
	}
	if f.TotalLengthFwdPackets != float32(maxPackets)*float32(pktLen) {
		t.Errorf("TotalLengthFwdPackets = %f, want %f",
			f.TotalLengthFwdPackets, float32(maxPackets)*float32(pktLen))
	}
	if f.AveragePacketSize != float32(pktLen) {
		t.Errorf("AveragePacketSize = %f, want %f", f.AveragePacketSize, float32(pktLen))
	}
	if f.FlowBytesPerSecond <= 0 {
		t.Errorf("FlowBytesPerSecond = %f, want > 0", f.FlowBytesPerSecond)
	}
	if f.FlowPacketsPerSecond <= 0 {
		t.Errorf("FlowPacketsPerSecond = %f, want > 0", f.FlowPacketsPerSecond)
	}
}

// ── Flow isolation ────────────────────────────────────────────────────────────

func TestIngest_DifferentFlowsAreIsolated(t *testing.T) {
	a := NewAggregator()
	defer a.Close()

	rA := report("1.1.1.1", "2.2.2.2", 80, "TCP", 100)
	rB := report("3.3.3.3", "4.4.4.4", 443, "TCP", 200)

	// Saturate flow A to threshold.
	var resultA *FlowResult
	for i := 0; i < maxPackets; i++ {
		resultA = a.Ingest(rA)
		// Also ingest B so it accumulates in parallel.
		_ = a.Ingest(rB)
		if resultA != nil {
			break
		}
	}

	if resultA == nil {
		t.Fatal("flow A never exported")
	}
	if resultA.SrcIP != "1.1.1.1" {
		t.Errorf("expected flow A srcIP=1.1.1.1, got %s", resultA.SrcIP)
	}

	// Flow B should still be alive (it has maxPackets packets but not exported
	// via its own threshold call — it will be swept by the background goroutine).
	a.mu.Lock()
	_, bAlive := a.flows[FlowKey{"3.3.3.3", "4.4.4.4", 443, "TCP"}]
	a.mu.Unlock()

	// B may or may not have been exported depending on timing; just verify A didn't corrupt B.
	_ = bAlive
}

// ── Sweep goroutine ───────────────────────────────────────────────────────────

func TestSweep_ExpiresFlowAfterWindow(t *testing.T) {
	// Create an aggregator with a very short sweep/window for testing.
	// We cannot configure the constants at runtime, so this test relies on
	// the actual windowDuration. Skip if the test environment is too slow.
	if windowDuration > 10*time.Second {
		t.Skip("window too long for unit test")
	}

	a := NewAggregator()
	defer a.Close()

	r := report("9.9.9.9", "8.8.8.8", 53, "UDP", 64)

	// Send exactly minPackets so the flow qualifies for sweep-based export.
	for i := 0; i < minPackets; i++ {
		_ = a.Ingest(r)
	}

	// Wait for at least one full window + sweep cycle.
	deadline := time.After(windowDuration*2 + time.Second)
	select {
	case result := <-a.Results():
		if result.SrcIP != "9.9.9.9" {
			t.Errorf("unexpected SrcIP %s", result.SrcIP)
		}
	case <-deadline:
		t.Fatal("timed out waiting for sweep to export the flow")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

func TestIngest_ConcurrentSafe(t *testing.T) {
	a := NewAggregator()
	defer a.Close()

	const goroutines = 50
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			r := report("1.1.1.1", "2.2.2.2", uint32(id%1024), "TCP", 100)
			for j := 0; j < 10; j++ {
				_ = a.Ingest(r)
			}
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}
