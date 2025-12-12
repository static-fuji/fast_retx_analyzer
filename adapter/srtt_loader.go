package adapter

import (
	"encoding/csv"
	"os"
	"sort"
	"strconv"
	"fr_analysis/domain"
)

type CsvSrttRepository struct {
	filename string
}

func NewCsvSrttRepository(filename string) *CsvSrttRepository {
	return &CsvSrttRepository{filename: filename}
}

func (r *CsvSrttRepository) LoadSrttEntries() ([]domain.SrttEntry, error) {
	file, err := os.Open(r.filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	if _, err := reader.Read(); err != nil {
		return nil, err
	}

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var entries []domain.SrttEntry

	for _, record := range records {
		if len(record) < 2 {
			continue
		}
		
		t, err := strconv.ParseInt(record[0], 10, 64)
		if err != nil {
			continue
		}

		val, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			continue
		}

		entries = append(entries, domain.SrttEntry{
			TimeUs: t,
			Srtt:   val,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].TimeUs < entries[j].TimeUs
	})

	return entries, nil
}