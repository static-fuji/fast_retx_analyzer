package domain

import "time"

// パケット情報
type Packet struct {
	SrcIP      string
	DstIP      string
	SrcPort    int
	DstPort    int
	Seq        uint32
	Ack        uint32
	IsAck      bool
	PayloadLen int
	Timestamp  time.Time
}

// Fast Retransmissionの分析情報
type AnalysisResult struct {
	Seq      uint32
	Duration float64
	Conflict int // 0: No Conflict, 1: Spurious Retransmission
	RTO      int // 0: No RTO, 1: RTO Retransmission occurred
	FrTime   int64
}

// Congestion stateの情報
type CongestionEvent struct {
	TimeUs     int64  // Time of CA_RECOVERY
	NextState  string // Time of CA_LOSS
	NextTimeUs int64  // Time of changed next state
}

// TCPフロー識別子
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
}

func (k FlowKey) Reverse() FlowKey {
	return FlowKey{
		SrcIP:   k.DstIP,
		DstIP:   k.SrcIP,
		SrcPort: k.DstPort,
		DstPort: k.SrcPort,
	}
}