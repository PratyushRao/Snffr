package ai

type FlowFeatures struct {
	// DestinationPort is the TCP/UDP destination port of the flow.
	DestinationPort float32

	// FlowDuration is the total duration of the flow in microseconds.
	FlowDuration float32

	// TotalFwdPackets is the total number of packets sent in the forward direction.
	TotalFwdPackets float32

	// TotalLengthFwdPackets is the total byte length of all forward packets.
	TotalLengthFwdPackets float32

	// FlowBytesPerSecond is the byte-throughput of the flow (bytes / second).
	FlowBytesPerSecond float32

	// FlowPacketsPerSecond is the packet-rate of the flow (packets / second).
	FlowPacketsPerSecond float32

	// AveragePacketSize is the mean packet size across all packets in the flow.
	AveragePacketSize float32
}

func ToFeatureVector(f FlowFeatures) []float32 {
	return []float32{
		f.DestinationPort,
		f.FlowDuration,
		f.TotalFwdPackets,
		f.TotalLengthFwdPackets,
		f.FlowBytesPerSecond,
		f.FlowPacketsPerSecond,
		f.AveragePacketSize,
	}
}


const (
	// numFeatures is the exact number of float32 inputs the model expects.
	numFeatures = 7

	// aiRiskNormal is the AI risk score assigned when the model predicts a normal
	// flow (IsolationForest label == 1).
	aiRiskNormal = 0

	// aiRiskAnomaly is the AI risk score assigned when the model predicts an
	// anomalous flow (IsolationForest label == -1).
	aiRiskAnomaly = 50
)

// mapLabelToRisk converts the IsolationForest integer label to a risk score.
//
//	 1 → normal flow    → AI risk 0
//	-1 → anomalous flow → AI risk 50
func mapLabelToRisk(label int64) int {
	if label == 1 {
		return aiRiskNormal
	}
	return aiRiskAnomaly
}
