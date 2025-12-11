package adapter

import (
	"encoding/csv"
	"os"
	"strconv"
	"fr_analysis/domain"
)

type CsvResultRepository struct {
	file   *os.File
	writer *csv.Writer
}

func NewCsvResultRepository(filename string) (*CsvResultRepository, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)

	w.Write([]string{"SequenceNumber", "TimeDuration", "Conflict", "RTO"})
	w.Flush()

	return &CsvResultRepository{
		file:   f,
		writer: w,
	}, nil
}

func (r *CsvResultRepository) Save(result domain.AnalysisResult) error {
	seqStr := strconv.FormatUint(uint64(result.Seq), 10)
	durStr := strconv.FormatFloat(result.Duration, 'f', 9, 64)
	confStr := strconv.Itoa(result.Conflict)
	rtoStr := strconv.Itoa(result.RTO)

	err := r.writer.Write([]string{seqStr, durStr, confStr, rtoStr})
	if err == nil {
		r.writer.Flush()
	}
	return err
}

func (r *CsvResultRepository) Close() {
	r.writer.Flush()
	r.file.Close()
}