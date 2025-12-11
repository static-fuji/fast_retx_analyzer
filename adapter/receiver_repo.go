package adapter

import (
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ReceiverStats struct {
	SeqCounts map[uint32]int
}

type PcapReceiverRepository struct {
	filename string
}

func NewPcapReceiverRepository(filename string) *PcapReceiverRepository {
	return &PcapReceiverRepository{filename: filename}
}

func (r *PcapReceiverRepository) AnalyzeReceiver(targetSrcIP string) (*ReceiverStats, error) {
	handle, err := pcap.OpenOffline(r.filename)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	stats := &ReceiverStats{
		SeqCounts: make(map[uint32]int),
	}

	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ipLayer == nil || tcpLayer == nil {
			continue
		}

		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)

		if ip.SrcIP.String() != targetSrcIP {
			continue
		}

		if len(tcp.Payload) > 0 {
			stats.SeqCounts[tcp.Seq]++
		}
	}

	return stats, nil
}

func (r *PcapReceiverRepository) GetPacketCounts(targetSrcIP string) (map[uint32]int, error) {
	stats, err := r.AnalyzeReceiver(targetSrcIP)
	if err != nil {
		return nil, err
	}
	return stats.SeqCounts, nil
}