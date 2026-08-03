//go:build darwin

package traffic

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type NettopSampler struct {
	Command string
	Timeout time.Duration
}

func (s NettopSampler) Sample(ctx context.Context, pid int) (Counters, error) {
	if pid <= 0 {
		return Counters{}, fmt.Errorf("invalid process id: %d", pid)
	}
	command := strings.TrimSpace(s.Command)
	if command == "" {
		command = "nettop"
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	sampleCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(sampleCtx, command, "-P", "-L", "1", "-x", "-t", "external", "-p", strconv.Itoa(pid))
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(sampleCtx.Err(), context.DeadlineExceeded) || nettopWasKilled(err) {
			return Counters{}, ErrNoSample
		}
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return Counters{}, fmt.Errorf("macOS traffic monitor unavailable: %w: %s", err, detail)
		}
		return Counters{}, fmt.Errorf("macOS traffic monitor unavailable: %w", err)
	}
	counters, ok, err := ParseNettopCSV(output, pid)
	if err != nil {
		return Counters{}, err
	}
	if !ok {
		return Counters{}, ErrNoSample
	}
	return counters, nil
}

func nettopWasKilled(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "signal: killed")
}

func ParseNettopCSV(raw []byte, pid int) (Counters, bool, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1

	var bytesInIdx, bytesOutIdx int = -1, -1
	processIdx := 1
	var latest Counters
	found := false

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return Counters{}, false, err
		}
		if len(record) == 0 {
			continue
		}
		if strings.EqualFold(record[0], "time") {
			bytesInIdx, bytesOutIdx = -1, -1
			for idx, name := range record {
				switch strings.TrimSpace(name) {
				case "bytes_in":
					bytesInIdx = idx
				case "bytes_out":
					bytesOutIdx = idx
				}
			}
			continue
		}
		if bytesInIdx < 0 || bytesOutIdx < 0 || len(record) <= maxInt(bytesInIdx, bytesOutIdx, processIdx) {
			continue
		}
		if !nettopProcessMatchesPID(record[processIdx], pid) {
			continue
		}
		rx, err := parseNettopInt(record[bytesInIdx])
		if err != nil {
			return Counters{}, false, err
		}
		tx, err := parseNettopInt(record[bytesOutIdx])
		if err != nil {
			return Counters{}, false, err
		}
		latest = Counters{RXBytes: rx, TXBytes: tx}
		found = true
	}

	return latest, found, nil
}

func nettopProcessMatchesPID(value string, pid int) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	pidText := strconv.Itoa(pid)
	if value == pidText {
		return true
	}
	dot := strings.LastIndex(value, ".")
	return dot >= 0 && value[dot+1:] == pidText
}

func parseNettopInt(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid nettop byte counter %q: %w", value, err)
	}
	return parsed, nil
}

func maxInt(values ...int) int {
	maxValue := values[0]
	for _, value := range values[1:] {
		if value > maxValue {
			maxValue = value
		}
	}
	return maxValue
}
