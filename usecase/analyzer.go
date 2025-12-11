package usecase

import (
	"log"
	"time"

	"fr_analysis/domain"
)

type EventRepository interface {
	LoadEvents() ([]domain.CongestionEvent, error)
}

type PacketRepository interface {
	NextPacket() (*domain.Packet, error)
	HasPacketAt(targetSeq uint32, targetTime time.Time) (bool, error)
}

type ResultRepository interface {
	Save(result domain.AnalysisResult) error
}

type ReceiverRepository interface {
	GetPacketCounts(targetSrcIP string) (map[uint32]int, error)
}

type Analyzer struct {
	eventRepo  EventRepository
	packetRepo PacketRepository
	resultRepo ResultRepository
	recvRepo   ReceiverRepository
}

func NewAnalyzer(e EventRepository, p PacketRepository, r ResultRepository, recv ReceiverRepository) *Analyzer {
	return &Analyzer{
		eventRepo:  e,
		packetRepo: p,
		resultRepo: r,
		recvRepo:   recv,
	}
}

type flowState struct {
	IgnoreThreshold uint32
	PendingRetrans  bool
	RetransSeq      uint32
	StartTime       time.Time
	EventIndex      int
	CurrentEvent    domain.CongestionEvent
}

func (a *Analyzer) Run() error {
	events, err := a.eventRepo.LoadEvents()
	if err != nil {
		return err
	}
	log.Printf("Loaded %d events.", len(events))

	flows := make(map[domain.FlowKey]*flowState)
	var recvSeqCounts map[uint32]int
	recvLoaded := false

	var baseTime time.Time
	var isFirstPacket bool = true

	for {
		pkt, err := a.packetRepo.NextPacket()
		if err != nil || pkt == nil {
			break
		}

		if isFirstPacket {
			baseTime = pkt.Timestamp
			isFirstPacket = false
			log.Printf("Base Time set to: %v", baseTime)
		}

		if !recvLoaded && pkt.PayloadLen > 0 {
			counts, err := a.recvRepo.GetPacketCounts(pkt.SrcIP)
			if err == nil {
				recvSeqCounts = counts
			} else {
				recvSeqCounts = make(map[uint32]int)
			}
			recvLoaded = true
		}

		fwdKey := domain.FlowKey{
			SrcIP:   pkt.SrcIP,
			DstIP:   pkt.DstIP,
			SrcPort: pkt.SrcPort,
			DstPort: pkt.DstPort,
		}

		if _, exists := flows[fwdKey]; !exists {
			flows[fwdKey] = &flowState{}
		}
		state := flows[fwdKey]

		relativeTimeUs := pkt.Timestamp.Sub(baseTime).Microseconds()

		if pkt.PayloadLen > 0 {
			if state.EventIndex < len(events) && !state.PendingRetrans {
				targetEvent := events[state.EventIndex]
				
				if relativeTimeUs >= targetEvent.TimeUs {
					if pkt.Seq > state.IgnoreThreshold {
						state.PendingRetrans = true
						state.RetransSeq = pkt.Seq
						state.StartTime = pkt.Timestamp 
						state.CurrentEvent = targetEvent
						state.IgnoreThreshold = pkt.Seq
						state.EventIndex++
					}
				}
			}
		}

		if pkt.IsAck {
			revKey := fwdKey.Reverse()
			if targetState, exists := flows[revKey]; exists {
				if targetState.PendingRetrans {
					if pkt.Ack > targetState.RetransSeq {
						duration := pkt.Timestamp.Sub(targetState.StartTime)
						
						// Conflict判定
						conflict := 0
						if count, ok := recvSeqCounts[targetState.RetransSeq]; ok {
							if count > 1 {
								conflict = 1
							}
						}

						// RTO判定
						rto := 0
						if conflict == 1 {
							if targetState.CurrentEvent.NextState == "4" {
								
								rtoRelativeUs := targetState.CurrentEvent.NextTimeUs
								rtoAbsTime := baseTime.Add(time.Duration(rtoRelativeUs) * time.Microsecond)

								existsAtRto, err := a.packetRepo.HasPacketAt(
									targetState.RetransSeq,
									rtoAbsTime,
								)
								if err != nil {
									log.Printf("Error checking RTO packet: %v", err)
								}
								if existsAtRto {
									rto = 1
								}
							}
						}

						result := domain.AnalysisResult{
							Seq:      targetState.RetransSeq,
							Duration: duration.Seconds(),
							Conflict: conflict,
							RTO:      rto,
						}
						
						a.resultRepo.Save(result)
						targetState.PendingRetrans = false
					}
				}
			}
		}
	}
	return nil
}