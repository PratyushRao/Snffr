package ai

import (
	"reflect"
	"testing"
)

func TestToFeatureVector_Order(t *testing.T) {
	f := FlowFeatures{
		DestinationPort:       1,
		FlowDuration:          2,
		TotalFwdPackets:       3,
		TotalLengthFwdPackets: 4,
		FlowBytesPerSecond:    5,
		FlowPacketsPerSecond:  6,
		AveragePacketSize:     7,
	}

	want := []float32{1, 2, 3, 4, 5, 6, 7}
	got := ToFeatureVector(f)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ToFeatureVector order mismatch:\n got  %v\n want %v", got, want)
	}
}

func TestToFeatureVector_Length(t *testing.T) {
	v := ToFeatureVector(FlowFeatures{})
	if len(v) != numFeatures {
		t.Errorf("ToFeatureVector length = %d, want %d", len(v), numFeatures)
	}
}

func TestToFeatureVector_ImmutableCopy(t *testing.T) {
	f := FlowFeatures{DestinationPort: 42}
	v := ToFeatureVector(f)
	v[0] = 99 // mutate the returned slice

	// A second call must not be affected by the previous mutation.
	v2 := ToFeatureVector(f)
	if v2[0] != 42 {
		t.Errorf("ToFeatureVector returned a shared slice (not a copy)")
	}
}

func TestMapLabelToRisk(t *testing.T) {
	tests := []struct {
		label    int64
		wantRisk int
	}{
		{label: 1, wantRisk: aiRiskNormal},
		{label: -1, wantRisk: aiRiskAnomaly},
		{label: 0, wantRisk: aiRiskAnomaly}, // any label != 1 is treated as anomaly
	}

	for _, tc := range tests {
		got := mapLabelToRisk(tc.label)
		if got != tc.wantRisk {
			t.Errorf("mapLabelToRisk(%d) = %d, want %d", tc.label, got, tc.wantRisk)
		}
	}
}
