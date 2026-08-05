package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tunnelengine "tunnelcheck/engine/tunnelengine"

	"whitevpn-desktop/internal/model"
)

func TestDefaultValidatorRangesExposeOnlyNetworkAndHostCount(t *testing.T) {
	options, err := parseValidatorRangeOptions([]byte("network,country,as_name\n203.0.113.0/30,Iran,Hidden Company\n203.0.113.0/30,Iran,Duplicate\n198.51.100.7/32,Iran,Other Company\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []model.ValidatorRangeOption{
		{Range: "203.0.113.0/30", HostCount: 2},
		{Range: "198.51.100.7/32", HostCount: 1},
	}
	if !reflect.DeepEqual(options, want) {
		t.Fatalf("unexpected range options: got %#v want %#v", options, want)
	}
}

func TestValidatorRangeImportParsesIPv4CIDRInvalidAndDuplicates(t *testing.T) {
	result := parseValidatorRangeImportInput("203.0.113.10, 203.0.113.0/30\n203.0.113.0/30\nbad-entry\n2001:db8::1\n198.51.100.9/32\r\n")
	want := []model.ValidatorRangeOption{
		{Range: "203.0.113.10/32", HostCount: 1},
		{Range: "203.0.113.0/30", HostCount: 2},
		{Range: "198.51.100.9/32", HostCount: 1},
	}
	if !reflect.DeepEqual(result.Ranges, want) {
		t.Fatalf("unexpected imported ranges: got %#v want %#v", result.Ranges, want)
	}
	if result.TotalCount != 6 || result.InvalidCount != 2 || result.DuplicateCount != 1 {
		t.Fatalf("unexpected import counts: total=%d invalid=%d duplicates=%d", result.TotalCount, result.InvalidCount, result.DuplicateCount)
	}
	if !reflect.DeepEqual(result.Invalid, []string{"bad-entry", "2001:db8::1"}) {
		t.Fatalf("unexpected invalid samples: %#v", result.Invalid)
	}
}

func TestValidatorRangeImportSupportsCSVNetworkColumn(t *testing.T) {
	result := parseValidatorRangeImportInput("network,country,as_name\n203.0.113.10,Iran,Hidden Company\n198.51.100.0/30,Iran,Other Company\n")
	want := []model.ValidatorRangeOption{
		{Range: "203.0.113.10/32", HostCount: 1},
		{Range: "198.51.100.0/30", HostCount: 2},
	}
	if !reflect.DeepEqual(result.Ranges, want) {
		t.Fatalf("unexpected imported CSV ranges: got %#v want %#v", result.Ranges, want)
	}
	if result.TotalCount != 2 || result.InvalidCount != 0 || result.DuplicateCount != 0 {
		t.Fatalf("unexpected CSV import counts: total=%d invalid=%d duplicates=%d", result.TotalCount, result.InvalidCount, result.DuplicateCount)
	}
}

func TestValidatorRangeSelectionAcceptsBundledLargeIPv4Ranges(t *testing.T) {
	ranges, err := normalizeValidatorRangeSelection([]string{"5.96.0.0/11", "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ranges, []string{"5.96.0.0/11", "203.0.113.10/32"}) {
		t.Fatalf("unexpected normalized ranges: %#v", ranges)
	}
	if _, err := normalizeValidatorRangeSelection([]string{"10.0.0.0/8"}); err == nil {
		t.Fatal("expected /8 to be rejected")
	}
}

func TestValidatorRangeEndpointsExpandCIDR(t *testing.T) {
	count, err := validatorRangeEndpointCount([]string{"203.0.113.0/30"}, []int{443, 8443})
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("expected endpoint count 4, got %d", count)
	}
	count, err = validatorRangeEndpointCount([]string{"5.96.0.0/11"}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	if count != 2097150 {
		t.Fatalf("expected /11 endpoint count 2097150, got %d", count)
	}
	if _, err := validatorRangeEndpointCount([]string{"5.64.0.0/10"}, []int{443}); err == nil {
		t.Fatal("expected /10 to exceed the 4 million endpoint cap")
	}
	endpoints, err := validatorEndpointsFromRanges([]string{"203.0.113.0/30"}, []int{443, 8443}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.ValidatorEndpointInput{
		{Host: "203.0.113.1", Port: 443, SNI: "example.com"},
		{Host: "203.0.113.1", Port: 8443, SNI: "example.com"},
		{Host: "203.0.113.2", Port: 443, SNI: "example.com"},
		{Host: "203.0.113.2", Port: 8443, SNI: "example.com"},
	}
	if !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("unexpected endpoints: got %#v want %#v", endpoints, want)
	}
}

func TestValidatorRangePortsNormalizeAndDeduplicate(t *testing.T) {
	ports, err := normalizeValidatorRangePorts([]int{443, 2053, 443}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{443, 2053}) {
		t.Fatalf("unexpected ports: %#v", ports)
	}
	if _, err := normalizeValidatorRangePorts([]int{0}, 0); err == nil {
		t.Fatal("expected invalid port to be rejected")
	}
}

func TestNormalizeValidatorRequestRejectsInvalidEndpoint(t *testing.T) {
	_, _, err := normalizeValidatorRequest(model.ValidatorRequest{
		Endpoints: []model.ValidatorEndpointInput{{Host: "example.com", Port: 70000}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("expected invalid port error, got %v", err)
	}
}

func TestNormalizeValidatorRequestDefaultsMissingPort(t *testing.T) {
	endpoints, options, err := normalizeValidatorRequest(model.ValidatorRequest{
		Endpoints: []model.ValidatorEndpointInput{{Host: "example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoints[0].Port != defaultValidatorPort {
		t.Fatalf("expected default port %d, got %d", defaultValidatorPort, endpoints[0].Port)
	}
	if options.Retries != 1 {
		t.Fatalf("expected default retries 1, got %d", options.Retries)
	}
}

func TestNormalizeValidatorRequestCapsOptions(t *testing.T) {
	endpoints, options, err := normalizeValidatorRequest(model.ValidatorRequest{
		Endpoints: []model.ValidatorEndpointInput{{Host: "example.com.", Port: 443}},
		Options: model.ValidatorOptions{
			Retries:       99,
			TimeoutMillis: 1,
			WorkerCount:   999,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoints[0].Host != "example.com" {
		t.Fatalf("expected trimmed host, got %q", endpoints[0].Host)
	}
	if options.Retries != 8 || options.TimeoutMillis != 600 || options.WorkerCount != 999 || options.AdaptiveLimit != 999 {
		t.Fatalf("unexpected normalized options: %#v", options)
	}
}

func TestNormalizeValidatorRequestCapsWorkerCount(t *testing.T) {
	_, options, err := normalizeValidatorRequest(model.ValidatorRequest{
		Endpoints: []model.ValidatorEndpointInput{{Host: "example.com", Port: 443}},
		Options: model.ValidatorOptions{
			WorkerCount: maxValidatorWorkerCount + 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.WorkerCount != maxValidatorWorkerCount || options.AdaptiveLimit != maxValidatorWorkerCount {
		t.Fatalf("expected worker count cap %d, got %#v", maxValidatorWorkerCount, options)
	}
}

func TestNormalizeValidatorRequestAcceptsLegacyAdaptiveLimit(t *testing.T) {
	_, options, err := normalizeValidatorRequest(model.ValidatorRequest{
		Endpoints: []model.ValidatorEndpointInput{{Host: "example.com", Port: 443}},
		Options: model.ValidatorOptions{
			AdaptiveLimit: 12,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.WorkerCount != 12 || options.AdaptiveLimit != 12 {
		t.Fatalf("expected legacy adaptive limit to populate worker count, got %#v", options)
	}
}

func TestRecordValidatorResultCountsGradesWithoutUIRetention(t *testing.T) {
	app := &App{
		validatorState: model.ValidatorState{
			Status:  model.ValidatorRunning,
			Total:   6,
			Results: []model.ValidatorResult{},
		},
		validatorRunID: 1,
	}

	for idx, grade := range []string{"A+", "A", "B", "C", "D", "F"} {
		app.recordValidatorResult(context.Background(), 1, tunnelengine.ScanResult{
			Endpoint: fmt.Sprintf("203.0.113.%d:443", idx+1),
			Host:     fmt.Sprintf("203.0.113.%d", idx+1),
			Port:     443,
			Score: tunnelengine.ScoreResult{
				Grade:   grade,
				Numeric: 100 - idx,
			},
		}, model.ValidatorOptions{}, "")
	}

	state := app.GetValidatorState()
	if state.Completed != 6 {
		t.Fatalf("expected all results to count as completed, got %d", state.Completed)
	}
	if len(state.Results) != 0 {
		t.Fatalf("expected no UI-retained validator rows, got %#v", state.Results)
	}
	if state.GradeAPlus != 1 || state.GradeA != 1 || state.GradeB != 1 || state.GradeC != 1 || state.GradeF != 1 {
		t.Fatalf("unexpected grade counters: A+=%d A=%d B=%d C=%d F=%d", state.GradeAPlus, state.GradeA, state.GradeB, state.GradeC, state.GradeF)
	}
}

func TestValidatorCSVWriterWritesHeadersAndRows(t *testing.T) {
	writer, err := newValidatorCSVWriter(t.TempDir(), 1770000000000)
	if err != nil {
		t.Fatal(err)
	}
	err = writer.Write(context.Background(), validatorCSVRecord{
		Timestamp: time.Unix(1770000000, 123),
		SNI:       "scan.example.com",
		Result: tunnelengine.ScanResult{
			Endpoint: "203.0.113.9:443",
			Host:     "203.0.113.9",
			Port:     443,
			TCP:      tunnelengine.TCPResult{Success: true},
			TLS:      tunnelengine.TLSResult{Success: true},
			HTTP:     tunnelengine.HTTPResult{Success: true},
			UDP:      tunnelengine.UDPResult{Reachable: true},
			Metrics: tunnelengine.Metrics{
				RTTMs:              12,
				JitterMs:           3,
				PacketLossEstimate: 1.5,
				StabilityPercent:   98.5,
			},
			Score: tunnelengine.ScoreResult{
				Numeric:        90,
				Grade:          "A",
				Classification: "Tunnel Ready",
				Confidence:     0.95,
				Reasons:        []string{"tcp ok", "tls ok"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected one CSV row, got %d", rows)
	}
	records := readValidatorCSVRecords(t, writer.path)
	if !reflect.DeepEqual(records[0], validatorCSVHeader) {
		t.Fatalf("unexpected header:\ngot  %#v\nwant %#v", records[0], validatorCSVHeader)
	}
	row := records[1]
	values := map[string]string{}
	for idx, column := range records[0] {
		values[column] = row[idx]
	}
	for column, want := range map[string]string{
		"endpoint":       "203.0.113.9:443",
		"host":           "203.0.113.9",
		"port":           "443",
		"sni":            "scan.example.com",
		"ping_ms":        "12",
		"rtt_ms":         "12",
		"score":          "90",
		"grade":          "A",
		"classification": "Tunnel Ready",
		"tcp":            "true",
		"tls":            "true",
		"http":           "true",
		"udp":            "true",
		"confidence":     "0.95",
		"jitter_ms":      "3",
		"packet_loss":    "1.5",
		"stability":      "98.5",
		"reasons":        "tcp ok | tls ok",
	} {
		if values[column] != want {
			t.Fatalf("expected CSV %s=%q, got %q", column, want, values[column])
		}
	}
}

func TestValidatorRunWritesAllCSVRowsAndKeepsNoUIResults(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	_, ctx, runID, err := app.startValidatorRun("bulk", 106, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for idx := 1; idx <= 105; idx++ {
		app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
			Endpoint: fmt.Sprintf("203.0.113.%d:443", idx),
			Host:     fmt.Sprintf("203.0.113.%d", idx),
			Port:     443,
			TCP:      tunnelengine.TCPResult{Success: true},
			Score: tunnelengine.ScoreResult{
				Grade:          "A",
				Numeric:        idx,
				Classification: "Tunnel Ready",
			},
		}, model.ValidatorOptions{}, "")
	}
	app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
		Endpoint: "203.0.113.250:443",
		Host:     "203.0.113.250",
		Port:     443,
		Score: tunnelengine.ScoreResult{
			Grade:   "D",
			Numeric: 1,
		},
	}, model.ValidatorOptions{}, "")
	app.finishValidatorRun(runID, nil)

	state := app.GetValidatorState()
	if state.Completed != 106 || state.Retained != 106 {
		t.Fatalf("unexpected validator counters: completed=%d retained=%d", state.Completed, state.Retained)
	}
	if len(state.Results) != 0 {
		t.Fatalf("expected no UI-retained validator rows, got %d", len(state.Results))
	}
	if state.ResultsFileRows != 106 {
		t.Fatalf("expected 106 CSV rows, got %d", state.ResultsFileRows)
	}
	records := readValidatorCSVRecords(t, state.ResultsFilePath)
	if got := len(records) - 1; got != 106 {
		t.Fatalf("expected 106 data rows in CSV, got %d", got)
	}
	last := records[len(records)-1]
	values := map[string]string{}
	for idx, column := range records[0] {
		values[column] = last[idx]
	}
	if values["host"] != "203.0.113.250" || values["grade"] != "D" {
		t.Fatalf("expected D result to be written to CSV, got %#v", values)
	}
}

func TestValidatorRunWritesDResultsToCSV(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	_, ctx, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
		Endpoint: "203.0.113.250:443",
		Host:     "203.0.113.250",
		Port:     443,
		Score: tunnelengine.ScoreResult{
			Grade:   "D",
			Numeric: 1,
		},
	}, model.ValidatorOptions{}, "")
	app.finishValidatorRun(runID, nil)

	state := app.GetValidatorState()
	if state.Completed != 1 || state.Retained != 1 || len(state.Results) != 0 {
		t.Fatalf("expected D result to write without UI retention, got completed=%d retained=%d results=%d", state.Completed, state.Retained, len(state.Results))
	}
	if state.ResultsFileRows != 1 {
		t.Fatalf("expected D result to write one CSV row, got %d", state.ResultsFileRows)
	}
	records := readValidatorCSVRecords(t, state.ResultsFilePath)
	if got := len(records) - 1; got != 1 {
		t.Fatalf("expected one CSV data row, got %d", got)
	}
	values := map[string]string{}
	for idx, column := range records[0] {
		values[column] = records[1][idx]
	}
	if values["host"] != "203.0.113.250" || values["grade"] != "D" {
		t.Fatalf("expected D result in CSV, got %#v", values)
	}
}

func TestValidatorRunSkipsFResultsInCSV(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	_, ctx, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
		Endpoint: "203.0.113.250:443",
		Host:     "203.0.113.250",
		Port:     443,
		Score: tunnelengine.ScoreResult{
			Grade:   "F",
			Numeric: 1,
		},
	}, model.ValidatorOptions{}, "")
	app.finishValidatorRun(runID, nil)

	state := app.GetValidatorState()
	if state.Completed != 1 || state.Retained != 0 || state.GradeF != 1 || len(state.Results) != 0 {
		t.Fatalf("expected F result to count but not persist, got completed=%d retained=%d gradeF=%d results=%d", state.Completed, state.Retained, state.GradeF, len(state.Results))
	}
	if state.ResultsFileRows != 0 {
		t.Fatalf("expected F result to write no CSV rows, got %d", state.ResultsFileRows)
	}
	records := readValidatorCSVRecords(t, state.ResultsFilePath)
	if got := len(records) - 1; got != 0 {
		t.Fatalf("expected no CSV data rows, got %d", got)
	}
}

func TestValidatorRunWritesPeriodicMetadataForActiveCSV(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	_, ctx, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	app.validatorMu.Lock()
	app.validatorLastMetadataWrite = time.Now().Add(-validatorResultMetaInterval)
	app.validatorMu.Unlock()
	app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
		Endpoint: "203.0.113.9:443",
		Host:     "203.0.113.9",
		Port:     443,
		TCP:      tunnelengine.TCPResult{Success: true},
		Score: tunnelengine.ScoreResult{
			Grade:   "A",
			Numeric: 90,
		},
	}, model.ValidatorOptions{}, "")
	state := app.GetValidatorState()
	meta := readValidatorMeta(t, validatorResultMetaPath(state.ResultsFilePath))
	if meta.Status != model.ValidatorRunning || meta.Rows != 1 {
		t.Fatalf("expected running metadata with one row, got %#v", meta)
	}
	app.finishValidatorRun(runID, nil)
}

func TestValidatorRunWritesMetadataForDResults(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	_, ctx, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	app.validatorMu.Lock()
	app.validatorLastMetadataWrite = time.Now().Add(-validatorResultMetaInterval)
	app.validatorMu.Unlock()
	app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
		Endpoint: "203.0.113.9:443",
		Host:     "203.0.113.9",
		Port:     443,
		Score: tunnelengine.ScoreResult{
			Grade:   "D",
			Numeric: 1,
		},
	}, model.ValidatorOptions{}, "")
	state := app.GetValidatorState()
	meta := readValidatorMeta(t, validatorResultMetaPath(state.ResultsFilePath))
	if meta.Status != model.ValidatorRunning || meta.Completed != 1 || meta.Rows != 1 {
		t.Fatalf("expected running metadata to update for D result, got %#v", meta)
	}
	app.finishValidatorRun(runID, nil)
}

func TestValidatorRunWritesMetadataForSkippedFResults(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	_, ctx, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	app.validatorMu.Lock()
	app.validatorLastMetadataWrite = time.Now().Add(-validatorResultMetaInterval)
	app.validatorMu.Unlock()
	app.recordValidatorResult(ctx, runID, tunnelengine.ScanResult{
		Endpoint: "203.0.113.9:443",
		Host:     "203.0.113.9",
		Port:     443,
		Score: tunnelengine.ScoreResult{
			Grade:   "F",
			Numeric: 1,
		},
	}, model.ValidatorOptions{}, "")
	state := app.GetValidatorState()
	meta := readValidatorMeta(t, validatorResultMetaPath(state.ResultsFilePath))
	if meta.Status != model.ValidatorRunning || meta.Completed != 1 || meta.Rows != 0 || meta.GradeF != 1 {
		t.Fatalf("expected running metadata to count skipped F result without rows, got %#v", meta)
	}
	app.finishValidatorRun(runID, nil)
}

func TestEmitValidatorProgressCombinesPendingResults(t *testing.T) {
	app := &App{}
	var events []string
	var progress validatorProgressEvent
	app.emitHook = func(name string, payload any) {
		events = append(events, name)
		if name == "validator:progress" {
			progress = payload.(validatorProgressEvent)
		}
	}

	app.emitValidatorProgress(validatorProgressEvent{StartedAt: 1, Completed: 1}, []model.ValidatorResult{
		{Endpoint: "203.0.113.1:443", Host: "203.0.113.1", Port: 443},
	})

	if !reflect.DeepEqual(events, []string{"validator:progress"}) {
		t.Fatalf("expected one combined progress event, got %#v", events)
	}
	if !progress.AppendResults || len(progress.Results) != 1 || progress.Results[0].Endpoint != "203.0.113.1:443" {
		t.Fatalf("expected pending results on progress event, got %#v", progress)
	}
}

func TestValidatorCSVMetadataFinalizedForCancelledAndFailedRuns(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		cancel bool
		err    error
		status string
	}{
		{name: "cancelled", cancel: true, err: context.Canceled, status: model.ValidatorCancelled},
		{name: "failed", err: errors.New("boom"), status: model.ValidatorFailed},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			app := &App{validatorResultsDir: t.TempDir()}
			_, _, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.cancel {
				if _, err := app.CancelValidatorScan(); err != nil {
					t.Fatal(err)
				}
			}
			app.finishValidatorRun(runID, testCase.err)
			state := app.GetValidatorState()
			if state.Status != testCase.status {
				t.Fatalf("expected status %s, got %s", testCase.status, state.Status)
			}
			meta := readValidatorMeta(t, validatorResultMetaPath(state.ResultsFilePath))
			if meta.Status != testCase.status {
				t.Fatalf("expected metadata status %s, got %s", testCase.status, meta.Status)
			}
		})
	}
}

func TestValidatorResultFilesListSortsAndDeleteRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "validator-20260101-000000.csv")
	secondPath := filepath.Join(dir, "validator-20260102-000000.csv")
	if err := os.WriteFile(firstPath, []byte("timestamp,endpoint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("timestamp,endpoint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeValidatorResultMetadata(firstPath, model.ValidatorState{
		Status:          model.ValidatorCompleted,
		Mode:            "bulk",
		Total:           10,
		Completed:       10,
		ResultsFileRows: 10,
		StartedAt:       1770000000000,
		FinishedAt:      1770000001000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeValidatorResultMetadata(secondPath, model.ValidatorState{
		Status:          model.ValidatorCancelled,
		Mode:            "bulk",
		Total:           20,
		Completed:       5,
		ResultsFileRows: 5,
		StartedAt:       1770000100000,
		FinishedAt:      1770000101000,
	}); err != nil {
		t.Fatal(err)
	}

	app := &App{validatorResultsDir: dir}
	files, err := app.ListValidatorResultFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Name != filepath.Base(secondPath) || files[1].Name != filepath.Base(firstPath) {
		t.Fatalf("unexpected sorted history: %#v", files)
	}
	if _, err := app.DeleteValidatorResultFile("../validator-20260101-000000.csv"); err == nil {
		t.Fatal("expected traversal delete to be rejected")
	}
	files, err = app.DeleteValidatorResultFile(filepath.Base(secondPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != filepath.Base(firstPath) {
		t.Fatalf("expected delete to remove only selected file, got %#v", files)
	}
	if _, err := os.Stat(secondPath); !os.IsNotExist(err) {
		t.Fatalf("expected deleted CSV to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(validatorResultMetaPath(secondPath)); !os.IsNotExist(err) {
		t.Fatalf("expected deleted metadata to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(firstPath); err != nil {
		t.Fatalf("expected other CSV to remain: %v", err)
	}
}

func TestValidatorResultFilesMarkStaleRunningMetadataInterrupted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator-20260103-000000.csv")
	if err := os.WriteFile(path, []byte("timestamp,endpoint\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeValidatorResultMetadata(path, model.ValidatorState{
		Status:          model.ValidatorRunning,
		Mode:            "bulk",
		Total:           10,
		Completed:       5,
		ResultsFileRows: 5,
		StartedAt:       1770000200000,
		ResultsFileName: filepath.Base(path),
	}); err != nil {
		t.Fatal(err)
	}
	app := &App{validatorResultsDir: dir}
	files, err := app.ListValidatorResultFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Status != validatorResultInterrupted {
		t.Fatalf("expected stale running file to be interrupted, got %#v", files)
	}
}

func TestDeleteValidatorResultFileRejectsActiveRun(t *testing.T) {
	app := &App{validatorResultsDir: t.TempDir()}
	state, _, runID, err := app.startValidatorRun("bulk", 1, []int{443}, model.ValidatorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DeleteValidatorResultFile(state.ResultsFileName); err == nil {
		t.Fatal("expected active validator CSV delete to be rejected")
	}
	app.finishValidatorRun(runID, context.Canceled)
}

func TestWindowsValidatorWorkerCeilingCapsHeavyProtocolScans(t *testing.T) {
	plan := newValidatorWorkerPlanForOS("windows", model.ValidatorOptions{
		WorkerCount:     256,
		EnableUDP:       true,
		EnableQUIC:      true,
		EnableDNS:       true,
		EnableWebSocket: true,
	})
	if plan.requested != 256 || plan.ceiling != 150 || plan.effective != 128 || !plan.adaptive {
		t.Fatalf("unexpected heavy Windows worker plan: %#v", plan)
	}
}

func TestValidatorScanResultDetectsSocketPressure(t *testing.T) {
	if !validatorScanResultHasPressure(tunnelengine.ScanResult{
		TCP: tunnelengine.TCPResult{
			Attempts: []tunnelengine.AttemptMetric{{ErrorCategory: "socket_pressure"}},
		},
	}) {
		t.Fatal("expected socket pressure to be detected")
	}
}

func readValidatorCSVRecords(t *testing.T, path string) [][]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func readValidatorMeta(t *testing.T, path string) validatorResultFileMeta {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta validatorResultFileMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return meta
}
