package adapter

import (
	"encoding/csv"
	"os"
	"sort"
	"strconv"
	"fr_analysis/domain"
)

type CsvEventRepository struct {
	filename string
}

func NewCsvEventRepository(filename string) *CsvEventRepository {
	return &CsvEventRepository{filename: filename}
}

func (r *CsvEventRepository) LoadEvents() ([]domain.CongestionEvent, error) {
	file, err := os.Open(r.filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// ヘッダー読み飛ばし
	if _, err := reader.Read(); err != nil {
		return nil, err
	}

	// 全行読み込み（先読みのため）
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var events []domain.CongestionEvent

	for i := 0; i < len(records); i++ {
		timeStr := records[i][0]
		congStateStr := records[i][1]

		if congStateStr == "3" {
			t, err := strconv.ParseInt(timeStr, 10, 64)
			if err != nil {
				continue
			}

			nextState := ""
			var nextTime int64 = 0

			for j := i + 1; j < len(records); j++ {
				nextStateStr := records[j][1]

				if nextStateStr != "3" {
					nextState = nextStateStr
					nt, _ := strconv.ParseInt(records[j][0], 10, 64)
					nextTime = nt
					break 
				}
			}

			events = append(events, domain.CongestionEvent{
				TimeUs:     t,
				NextState:  nextState,
				NextTimeUs: nextTime,
			})
		}
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].TimeUs < events[j].TimeUs
	})

	return events, nil
}