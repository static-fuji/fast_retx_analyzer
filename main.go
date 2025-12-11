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
	// コマンドライン引数の定義
	srcPcapPath := flag.String("source", "", "Path to the Sender PCAP file (Required)")
	sinkPcapPath := flag.String("sink", "", "Path to the Receiver PCAP file (Required)")
	csvPath := flag.String("csv", "", "Path to the TCP congestion state CSV file (Required)")
	outPath := flag.String("out", "result.csv", "Path to the output CSV file (Default: result.csv)")

	flag.Parse()

	if *srcPcapPath == "" || *csvPath == "" || *sinkPcapPath == "" {
		fmt.Fprintln(os.Stderr, "Error: missing required arguments.")
		fmt.Fprintln(os.Stderr, "Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	eventRepo := adapter.NewCsvEventRepository(*csvPath)

	srcRepo, err := adapter.NewPcapRepository(*srcPcapPath)
	if err != nil {
		log.Fatalf("Failed to open sender pcap: %v", err)
	}
	defer srcRepo.Close()

	sinkRepo := adapter.NewPcapReceiverRepository(*sinkPcapPath)

	resultRepo, err := adapter.NewCsvResultRepository(*outPath)
	if err != nil {
		log.Fatalf("Failed to create result file: %v", err)
	}
	defer resultRepo.Close()

	analyzer := usecase.NewAnalyzer(eventRepo, srcRepo, resultRepo, sinkRepo)

	log.Printf("Starting analysis...\n Source: %s\n Sink:   %s\n CSV:    %s", *srcPcapPath, *sinkPcapPath, *csvPath)
	if err := analyzer.Run(); err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}
	log.Println("Analysis complete.")
}