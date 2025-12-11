package adapter

import (
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"fr_analysis/domain"
)

type PcapRepository struct {
	filename string // ファイル名を保持しておく（再オープン用）
	handle   *pcap.Handle
	source   *gopacket.PacketSource
}

func NewPcapRepository(filename string) (*PcapRepository, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	return &PcapRepository{
		filename: filename,
		handle:   handle,
		source:   source,
	}, nil
}

func (r *PcapRepository) Close() {
	r.handle.Close()
}

func (r *PcapRepository) NextPacket() (*domain.Packet, error) {
	packet, err := r.source.NextPacket()
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return r.NextPacket()
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	return &domain.Packet{
		SrcIP:      ip.SrcIP.String(),
		DstIP:      ip.DstIP.String(),
		SrcPort:    int(tcp.SrcPort),
		DstPort:    int(tcp.DstPort),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		IsAck:      tcp.ACK,
		PayloadLen: len(tcp.Payload),
		Timestamp:  packet.Metadata().CaptureInfo.Timestamp,
	}, nil
}

func (r *PcapRepository) HasPacketAt(targetSeq uint32, targetTime time.Time) (bool, error) {
	handle, err := pcap.OpenOffline(r.filename)
	if err != nil {
		return false, err
	}
	defer handle.Close()

	// フィルタが正常に動作しない;;
	// if err := handle.SetBPFFilter("tcp"); err != nil { ... }

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	
	targetTimeUs := targetTime.UnixMicro()

	// 許容誤差範囲
	const timeWindowUs = 500 * 1000 // 500ms

	for {
		packet, err := source.NextPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		
		pktTimeUs := packet.Metadata().CaptureInfo.Timestamp.UnixMicro()

		if pktTimeUs < targetTimeUs {
			continue
		}
		//許容誤差範囲を超えたら該当セグメントに関するRTO再送が無いと判断
		if pktTimeUs > targetTimeUs+timeWindowUs {
			break
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		if tcp.Seq == targetSeq && len(tcp.Payload) > 0 {
			return true, nil
		}
	}

	return false, nil
}