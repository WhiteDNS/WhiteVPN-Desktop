package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tunnelengine "tunnelcheck/engine/tunnelengine"

	"whitevpn-desktop/internal/model"
)

const (
	validatorUIResultLimit          = 100
	validatorResultsDirName         = "validator-results"
	validatorResultFilePrefix       = "validator-"
	validatorResultCSVExt           = ".csv"
	validatorResultMetaExt          = ".json"
	validatorResultWriteBufferSize  = 1 << 20
	validatorResultWriteChannelSize = 4096
	validatorResultFlushInterval    = time.Second
	validatorResultMetaRowInterval  = 10000
	validatorResultMetaInterval     = 10 * time.Second
	validatorResultInterrupted      = "interrupted"
)

var validatorCSVHeader = []string{
	"timestamp",
	"endpoint",
	"host",
	"port",
	"sni",
	"ping_ms",
	"rtt_ms",
	"score",
	"grade",
	"classification",
	"tcp",
	"tls",
	"http",
	"websocket",
	"udp",
	"quic",
	"dns",
	"false_positive",
	"confidence",
	"jitter_ms",
	"packet_loss",
	"stability",
	"reasons",
	"errors",
}

type validatorCSVRecord struct {
	Timestamp time.Time
	SNI       string
	Result    tunnelengine.ScanResult
}

type validatorCSVCloseResult struct {
	rows int
	err  error
}

type validatorCSVWriter struct {
	name       string
	runName    string
	path       string
	records    chan validatorCSVRecord
	closed     chan struct{}
	done       chan validatorCSVCloseResult
	closeOnce  sync.Once
	closeState validatorCSVCloseResult

	errMu    sync.Mutex
	writeErr error
}

type validatorResultFileMeta struct {
	Name             string `json:"name"`
	RunName          string `json:"runName,omitempty"`
	Part             int    `json:"part"`
	Rows             int    `json:"rows"`
	Status           string `json:"status"`
	Mode             string `json:"mode"`
	Total            int    `json:"total"`
	Completed        int    `json:"completed"`
	Retained         int    `json:"retained"`
	Ready            int    `json:"ready"`
	BestScore        int    `json:"bestScore"`
	GradeAPlus       int    `json:"gradeAPlus"`
	GradeA           int    `json:"gradeA"`
	GradeB           int    `json:"gradeB"`
	GradeC           int    `json:"gradeC"`
	GradeF           int    `json:"gradeF"`
	StartedAt        int64  `json:"startedAt"`
	FinishedAt       int64  `json:"finishedAt"`
	ResultsFileName  string `json:"resultsFileName,omitempty"`
	RequestedWorkers int    `json:"requestedWorkers"`
	EffectiveWorkers int    `json:"effectiveWorkers"`
	WorkerCeiling    int    `json:"workerCeiling"`
	PressureEvents   int    `json:"pressureEvents"`
}

func newValidatorCSVWriter(dir string, startedAt int64) (*validatorCSVWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create validator results directory: %w", err)
	}
	file, name, path, err := createValidatorCSVFile(dir, startedAt)
	if err != nil {
		return nil, err
	}
	buffered := bufio.NewWriterSize(file, validatorResultWriteBufferSize)
	csvWriter := csv.NewWriter(buffered)
	if err := csvWriter.Write(validatorCSVHeader); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write validator CSV header: %w", err)
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("flush validator CSV header: %w", err)
	}
	if err := buffered.Flush(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("flush validator CSV header: %w", err)
	}

	writer := &validatorCSVWriter{
		name:    name,
		runName: strings.TrimSuffix(name, validatorResultCSVExt),
		path:    path,
		records: make(chan validatorCSVRecord, validatorResultWriteChannelSize),
		closed:  make(chan struct{}),
		done:    make(chan validatorCSVCloseResult, 1),
	}
	go writer.run(file, buffered, csvWriter)
	return writer, nil
}

func createValidatorCSVFile(dir string, startedAt int64) (*os.File, string, string, error) {
	if startedAt <= 0 {
		startedAt = time.Now().UnixMilli()
	}
	base := validatorResultFilePrefix + time.UnixMilli(startedAt).Local().Format("20060102-150405")
	var lastErr error
	for idx := 0; idx < 1000; idx++ {
		name := base + validatorResultCSVExt
		if idx > 0 {
			name = fmt.Sprintf("%s-%03d%s", base, idx, validatorResultCSVExt)
		}
		path := filepath.Join(dir, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			return file, name, path, nil
		}
		lastErr = err
		if !os.IsExist(err) {
			break
		}
	}
	return nil, "", "", fmt.Errorf("create validator CSV file: %w", lastErr)
}

func (w *validatorCSVWriter) run(file *os.File, buffered *bufio.Writer, csvWriter *csv.Writer) {
	rows := 0
	ticker := time.NewTicker(validatorResultFlushInterval)
	defer ticker.Stop()
	defer func() {
		if recovered := recover(); recovered != nil {
			w.setErr(fmt.Errorf("validator CSV writer panic: %v", recovered))
		}
		flushErr := w.flush(buffered, csvWriter)
		closeErr := file.Close()
		err := w.Err()
		if err == nil {
			err = flushErr
		}
		if err == nil {
			err = closeErr
		}
		close(w.closed)
		w.done <- validatorCSVCloseResult{rows: rows, err: err}
	}()

	for {
		select {
		case record, ok := <-w.records:
			if !ok {
				return
			}
			if w.Err() != nil {
				continue
			}
			if err := csvWriter.Write(validatorCSVRecordRow(record)); err != nil {
				w.setErr(fmt.Errorf("write validator CSV row: %w", err))
				continue
			}
			rows++
		case <-ticker.C:
			if err := w.flush(buffered, csvWriter); err != nil {
				w.setErr(err)
			}
		}
	}
}

func (w *validatorCSVWriter) Write(ctx context.Context, record validatorCSVRecord) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}
	if err := w.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.closed:
		if err := w.Err(); err != nil {
			return err
		}
		return fmt.Errorf("validator CSV writer closed")
	case w.records <- record:
		return w.Err()
	}
}

func (w *validatorCSVWriter) Close() (int, error) {
	w.closeOnce.Do(func() {
		close(w.records)
		w.closeState = <-w.done
	})
	return w.closeState.rows, w.closeState.err
}

func (w *validatorCSVWriter) Err() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.writeErr
}

func (w *validatorCSVWriter) setErr(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	if w.writeErr == nil {
		w.writeErr = err
	}
	w.errMu.Unlock()
}

func (w *validatorCSVWriter) flush(buffered *bufio.Writer, csvWriter *csv.Writer) error {
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("flush validator CSV rows: %w", err)
	}
	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("flush validator CSV buffer: %w", err)
	}
	return nil
}

func validatorCSVRecordRow(record validatorCSVRecord) []string {
	result := record.Result
	dnsOK := result.DNS.UDPResponsive || result.DNS.TCPResponsive
	return []string{
		record.Timestamp.Format(time.RFC3339Nano),
		result.Endpoint,
		result.Host,
		strconv.Itoa(result.Port),
		strings.TrimSpace(record.SNI),
		formatValidatorCSVInt64(result.Metrics.RTTMs),
		formatValidatorCSVInt64(result.Metrics.RTTMs),
		strconv.Itoa(result.Score.Numeric),
		result.Score.Grade,
		result.Score.Classification,
		strconv.FormatBool(result.TCP.Success),
		strconv.FormatBool(result.TLS.Success),
		strconv.FormatBool(result.HTTP.Success),
		strconv.FormatBool(result.WebSocket.Success),
		strconv.FormatBool(result.UDP.Reachable),
		strconv.FormatBool(result.QUIC.Success),
		strconv.FormatBool(dnsOK),
		strconv.FormatBool(result.Score.FalsePositive),
		formatValidatorCSVFloat(result.Score.Confidence),
		formatValidatorCSVInt64(result.Metrics.JitterMs),
		formatValidatorCSVFloat(result.Metrics.PacketLossEstimate),
		formatValidatorCSVFloat(result.Metrics.StabilityPercent),
		strings.Join(result.Score.Reasons, " | "),
		strings.Join(result.Errors, " | "),
	}
}

func formatValidatorCSVInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}

func formatValidatorCSVFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func (a *App) validatorResultsDirectory() (string, error) {
	if a.validatorResultsDir != "" {
		return a.validatorResultsDir, nil
	}
	configDir := a.configDir
	if configDir == "" {
		var err error
		configDir, err = appConfigDir()
		if err != nil {
			return "", err
		}
		a.configDir = configDir
	}
	a.validatorResultsDir = filepath.Join(configDir, validatorResultsDirName)
	return a.validatorResultsDir, nil
}

func (a *App) writeValidatorCSVResult(ctx context.Context, runID int64, result tunnelengine.ScanResult, sni string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validatorResultShouldWriteCSV(result) {
		return false, nil
	}
	a.validatorMu.Lock()
	status := a.validatorState.Status
	active := a.validatorRunID == runID && (status == model.ValidatorRunning || status == model.ValidatorCancelled)
	writer := a.validatorResultWriter
	a.validatorMu.Unlock()
	if !active || writer == nil {
		return false, nil
	}
	if err := writer.Write(ctx, validatorCSVRecord{
		Timestamp: time.Now(),
		SNI:       sni,
		Result:    result,
	}); err != nil {
		return false, err
	}
	return true, nil
}

func validatorResultShouldWriteCSV(result tunnelengine.ScanResult) bool {
	return !strings.EqualFold(strings.TrimSpace(result.Score.Grade), "F")
}

func (a *App) failValidatorRun(runID int64, err error) {
	if err == nil {
		return
	}
	a.validatorMu.Lock()
	if a.validatorRunID != runID || a.validatorState.Status != model.ValidatorRunning {
		a.validatorMu.Unlock()
		return
	}
	a.validatorState.Status = model.ValidatorFailed
	a.validatorState.Paused = false
	a.validatorState.Error = err.Error()
	a.validatorState.FinishedAt = time.Now().UnixMilli()
	if a.validatorCancel != nil {
		a.validatorCancel()
		a.validatorCancel = nil
	}
	pending := a.takeValidatorPendingResultsLocked()
	state := cloneValidatorProgressState(a.validatorState)
	a.validatorMu.Unlock()
	a.emitValidatorProgress(state, pending)
}

func writeValidatorResultMetadata(path string, state model.ValidatorState) error {
	meta := validatorResultFileMeta{
		Name:             filepath.Base(path),
		RunName:          validatorResultRunName(filepath.Base(path)),
		Part:             state.ResultsFilePart,
		Rows:             state.ResultsFileRows,
		Status:           state.Status,
		Mode:             state.Mode,
		Total:            state.Total,
		Completed:        state.Completed,
		Retained:         state.Retained,
		Ready:            state.Ready,
		BestScore:        state.BestScore,
		GradeAPlus:       state.GradeAPlus,
		GradeA:           state.GradeA,
		GradeB:           state.GradeB,
		GradeC:           state.GradeC,
		GradeF:           state.GradeF,
		StartedAt:        state.StartedAt,
		FinishedAt:       state.FinishedAt,
		ResultsFileName:  state.ResultsFileName,
		RequestedWorkers: state.RequestedWorkers,
		EffectiveWorkers: state.EffectiveWorkers,
		WorkerCeiling:    state.WorkerCeiling,
		PressureEvents:   state.PressureEvents,
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	metaPath := validatorResultMetaPath(path)
	tmpPath := metaPath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, metaPath)
}

func validatorResultMetaPath(csvPath string) string {
	return strings.TrimSuffix(csvPath, validatorResultCSVExt) + validatorResultMetaExt
}

func (a *App) ListValidatorResultFiles() ([]model.ValidatorResultFile, error) {
	dir, err := a.validatorResultsDirectory()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []model.ValidatorResultFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	activeName, activeRunName := a.activeValidatorResultFile()
	files := make([]model.ValidatorResultFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !validatorResultFileNameValid(name) {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, validatorResultFileFromStat(path, info, activeName, activeRunName))
	}
	sort.SliceStable(files, func(i, j int) bool {
		left := files[i].StartedAt
		if left == 0 {
			left = files[i].ModifiedAt
		}
		right := files[j].StartedAt
		if right == 0 {
			right = files[j].ModifiedAt
		}
		if left == right {
			return files[i].Name > files[j].Name
		}
		return left > right
	})
	return files, nil
}

func validatorResultFileFromStat(path string, info os.FileInfo, activeName string, activeRunName string) model.ValidatorResultFile {
	name := filepath.Base(path)
	file := model.ValidatorResultFile{
		Name:       name,
		RunName:    validatorResultRunName(name),
		Part:       1,
		Path:       path,
		SizeBytes:  info.Size(),
		ModifiedAt: info.ModTime().UnixMilli(),
	}
	if meta, ok := readValidatorResultMetadata(validatorResultMetaPath(path)); ok {
		if strings.TrimSpace(meta.RunName) != "" {
			file.RunName = meta.RunName
		}
		if meta.Part > 0 {
			file.Part = meta.Part
		}
		file.Rows = meta.Rows
		file.Status = meta.Status
		file.Mode = meta.Mode
		file.Total = meta.Total
		file.Completed = meta.Completed
		file.Retained = meta.Retained
		file.Ready = meta.Ready
		file.BestScore = meta.BestScore
		file.StartedAt = meta.StartedAt
		file.FinishedAt = meta.FinishedAt
		file.ResultsFileName = meta.ResultsFileName
	}
	if file.Status == model.ValidatorRunning && name != activeName && file.RunName != activeRunName {
		file.Status = validatorResultInterrupted
		if file.FinishedAt == 0 {
			file.FinishedAt = file.ModifiedAt
		}
	}
	return file
}

func readValidatorResultMetadata(path string) (validatorResultFileMeta, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validatorResultFileMeta{}, false
	}
	var meta validatorResultFileMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return validatorResultFileMeta{}, false
	}
	return meta, true
}

func (a *App) OpenValidatorResultFile(name string) error {
	path, err := a.validatorResultFilePath(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return openSystemFile(path)
}

func (a *App) DeleteValidatorResultFile(name string) ([]model.ValidatorResultFile, error) {
	path, err := a.validatorResultFilePath(name)
	if err != nil {
		return nil, err
	}
	activeName, activeRunName := a.activeValidatorResultFile()
	fileRunName := validatorResultRunName(filepath.Base(path))
	active := activeName == filepath.Base(path) || (activeRunName != "" && activeRunName == fileRunName)
	if active {
		return nil, fmt.Errorf("cannot delete the active validator CSV")
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Remove(validatorResultMetaPath(path)); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return a.ListValidatorResultFiles()
}

func (a *App) validatorResultFilePath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !validatorResultFileNameValid(name) {
		return "", fmt.Errorf("invalid validator result file name")
	}
	dir, err := a.validatorResultsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func validatorResultFileNameValid(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return false
	}
	return strings.HasPrefix(name, validatorResultFilePrefix) && strings.HasSuffix(name, validatorResultCSVExt)
}

func validatorResultRunName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, validatorResultCSVExt)
	if idx := strings.LastIndex(name, "-part-"); idx > 0 {
		return name[:idx]
	}
	return name
}

func (a *App) activeValidatorResultFile() (string, string) {
	a.validatorMu.Lock()
	defer a.validatorMu.Unlock()
	if a.validatorResultWriter == nil {
		return "", ""
	}
	return a.validatorResultWriter.name, a.validatorResultWriter.runName
}

func openSystemFile(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	hideConsoleWindow(cmd)
	return cmd.Start()
}
