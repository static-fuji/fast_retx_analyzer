package domain

import "time"

type AnalysisResult struct {
	Seq                 uint32
	Duration            float64
	Conflict            int
	RTO                 int
	FrTime              int64
	Srtt                float64
	DiffSrttDuration    float64
}

type SrttEntry struct {
	TimeUs int64
	Srtt   float64
}

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

type CongestionEvent struct {
	TimeUs     int64
	NextState  string
	NextTimeUs int64
}

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