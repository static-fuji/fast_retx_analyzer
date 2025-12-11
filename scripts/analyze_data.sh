#!/bin/bash

# 引数が指定されているか確認
if [ -z "$1" ]; then
    echo "ERROR: Please specify the data in the argument"
    echo "USAGE: $0 <data>"
    exit 1
fi

DATA_DIR="$1"

# 1から100までループ処理
for i in {1..100}; do
    echo "Processing sample-${i}..."

    go run main.go \
      -pcap "${DATA_DIR}/sample-${i}/pcaps/-0-1.pcap" \
      -recv "${DATA_DIR}/sample-${i}/pcaps/-5-1.pcap" \
      -csv  "${DATA_DIR}/sample-${i}/tcp-cong-state.csv" \
      -out  "${DATA_DIR}/sample-${i}/fr_result.csv"

    if [ $? -ne 0 ]; then
        echo "WARNING: Processing of sample-${i} failed"
    fi
done

echo "Success"