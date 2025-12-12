package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"fr_analysis/adapter"
	"fr_analysis/usecase"
)

func main() {
	pcapPath := flag.String("pcap", "", "Path to the Sender PCAP file (Required)")
	recvPcapPath := flag.String("recv", "", "Path to the Receiver PCAP file (Required)")
	csvPath := flag.String("csv", "", "Path to the TCP congestion state CSV file (Required)")
	srttPath := flag.String("srtt", "", "Path to the SRTT CSV file (Required)")
	outPath := flag.String("out", "result.csv", "Path to the output CSV file (Default: result.csv)")

	flag.Parse()

	if *pcapPath == "" || *csvPath == "" || *recvPcapPath == "" || *srttPath == "" {
		fmt.Fprintln(os.Stderr, "Error: missing required arguments.")
		fmt.Fprintln(os.Stderr, "Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	eventRepo := adapter.NewCsvEventRepository(*csvPath)
	srttRepo := adapter.NewCsvSrttRepository(*srttPath)

	pcapRepo, err := adapter.NewPcapRepository(*pcapPath)
	if err != nil {
		log.Fatalf("Failed to open sender pcap: %v", err)
	}
	defer pcapRepo.Close()

	recvRepo := adapter.NewPcapReceiverRepository(*recvPcapPath)

	resultRepo, err := adapter.NewCsvResultRepository(*outPath)
	if err != nil {
		log.Fatalf("Failed to create result file: %v", err)
	}
	defer resultRepo.Close()

	analyzer := usecase.NewAnalyzer(eventRepo, srttRepo, pcapRepo, resultRepo, recvRepo)

	log.Printf("Starting analysis...\n Sender: %s\n Recv:   %s\n CSV:    %s\n SRTT:   %s", 
		*pcapPath, *recvPcapPath, *csvPath, *srttPath)
	
	if err := analyzer.Run(); err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}
	log.Println("Analysis complete.")
}