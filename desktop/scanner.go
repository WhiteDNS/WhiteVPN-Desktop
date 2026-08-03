package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	tunnelengine "tunnelcheck/engine/tunnelengine"

	"whitevpn-desktop/internal/model"
)

const (
	defaultValidatorPort            = 53
	defaultValidatorRangeCSVName    = "filtered_ipv4.csv"
	defaultValidatorWorkerCount     = 128
	maxValidatorWorkerCount         = 2048
	maxValidatorRangeHosts          = 4000000
	maxValidatorRangeSelectionHosts = 4000000
	validatorImportInvalidSampleMax = 12
	validatorStateEmitInterval      = 2 * time.Second
)

type validatorProgressEvent struct {
	Status           string                  `json:"status"`
	Paused           bool                    `json:"paused"`
	Mode             string                  `json:"mode"`
	Total            int                     `json:"total"`
	Completed        int                     `json:"completed"`
	Retained         int                     `json:"retained"`
	Ready            int                     `json:"ready"`
	BestScore        int                     `json:"bestScore"`
	GradeAPlus       int                     `json:"gradeAPlus"`
	GradeA           int                     `json:"gradeA"`
	GradeB           int                     `json:"gradeB"`
	GradeC           int                     `json:"gradeC"`
	GradeF           int                     `json:"gradeF"`
	Ports            []int                   `json:"ports,omitempty"`
	ResultsFileName  string                  `json:"resultsFileName,omitempty"`
	ResultsFilePath  string                  `json:"resultsFilePath,omitempty"`
	ResultsFileRows  int                     `json:"resultsFileRows"`
	ResultsFilePart  int                     `json:"resultsFilePart"`
	ResultsFileCount int                     `json:"resultsFileCount"`
	RequestedWorkers int                     `json:"requestedWorkers"`
	EffectiveWorkers int                     `json:"effectiveWorkers"`
	WorkerCeiling    int                     `json:"workerCeiling"`
	PressureEvents   int                     `json:"pressureEvents"`
	Error            string                  `json:"error"`
	StartedAt        int64                   `json:"startedAt"`
	FinishedAt       int64                   `json:"finishedAt"`
	Options          model.ValidatorOptions  `json:"options"`
	Results          []model.ValidatorResult `json:"results,omitempty"`
	AppendResults    bool                    `json:"appendResults,omitempty"`
}

func (a *App) GetValidatorState() model.ValidatorState {
	a.validatorMu.Lock()
	defer a.validatorMu.Unlock()
	return cloneValidatorState(a.validatorState)
}

func (a *App) GetDefaultValidatorRanges() ([]model.ValidatorRangeOption, error) {
	raw, err := readDefaultValidatorRangeCSV()
	if err != nil {
		return nil, err
	}
	return parseValidatorRangeOptions(raw)
}

func (a *App) ParseValidatorRangeInput(rawText string) model.ValidatorRangeImportResult {
	return parseValidatorRangeImportInput(rawText)
}

func (a *App) StartValidatorRangeScan(request model.ValidatorRangeRequest) (model.ValidatorState, error) {
	ranges, err := normalizeValidatorRangeSelection(request.Ranges)
	if err != nil {
		return a.GetValidatorState(), err
	}
	ports, err := normalizeValidatorRangePorts(request.Ports, request.Port)
	if err != nil {
		return a.GetValidatorState(), err
	}
	total, err := validatorRangeEndpointCount(ranges, ports)
	if err != nil {
		return a.GetValidatorState(), err
	}
	mode := strings.TrimSpace(request.Mode)
	if mode == "" {
		mode = "bulk"
	}
	options := normalizeValidatorOptions(request.Options)
	state, ctx, runID, err := a.startValidatorRun(mode, total, ports, options)
	if err != nil {
		return state, err
	}
	go a.runValidatorRangeBatch(ctx, runID, ranges, ports, request.SNI, options)
	return state, nil
}

func (a *App) StartValidatorScan(request model.ValidatorRequest) (model.ValidatorState, error) {
	endpoints, options, err := normalizeValidatorRequest(request)
	if err != nil {
		return a.GetValidatorState(), err
	}
	mode := strings.TrimSpace(request.Mode)
	if mode == "" {
		mode = "quick"
	}
	state, ctx, runID, err := a.startValidatorRun(mode, len(endpoints), validatorPortsFromEndpoints(endpoints), options)
	if err != nil {
		return state, err
	}

	go a.runValidatorBatch(ctx, runID, endpoints, options)
	return state, nil
}

func (a *App) startValidatorRun(mode string, total int, ports []int, options model.ValidatorOptions) (model.ValidatorState, context.Context, int64, error) {
	a.validatorMu.Lock()
	if a.validatorState.Status == model.ValidatorRunning || a.validatorResultWriter != nil {
		state := cloneValidatorState(a.validatorState)
		a.validatorMu.Unlock()
		return state, nil, 0, fmt.Errorf("validator is already running")
	}
	resultsDir, err := a.validatorResultsDirectory()
	if err != nil {
		state := cloneValidatorState(a.validatorState)
		a.validatorMu.Unlock()
		return state, nil, 0, err
	}
	startedAt := time.Now().UnixMilli()
	writer, err := newValidatorCSVWriter(resultsDir, startedAt)
	if err != nil {
		state := cloneValidatorState(a.validatorState)
		a.validatorMu.Unlock()
		return state, nil, 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	workerPlan := newValidatorWorkerPlan(options)
	a.validatorRunID++
	runID := a.validatorRunID
	a.validatorCancel = cancel
	a.validatorResultWriter = writer
	a.validatorDone = make(chan struct{})
	a.validatorLastEmit = time.Now()
	a.validatorLastMetadataWrite = time.Now()
	a.validatorPendingResults = nil
	a.validatorState = model.ValidatorState{
		Status:           model.ValidatorRunning,
		Paused:           false,
		Mode:             mode,
		Total:            total,
		Completed:        0,
		Retained:         0,
		Ready:            0,
		BestScore:        0,
		GradeAPlus:       0,
		GradeA:           0,
		GradeB:           0,
		GradeC:           0,
		GradeF:           0,
		Ports:            append([]int(nil), ports...),
		Results:          []model.ValidatorResult{},
		ResultsFileName:  writer.name,
		ResultsFilePath:  writer.path,
		ResultsFileRows:  0,
		ResultsFilePart:  1,
		ResultsFileCount: 1,
		RequestedWorkers: workerPlan.requested,
		EffectiveWorkers: workerPlan.effective,
		WorkerCeiling:    workerPlan.ceiling,
		PressureEvents:   0,
		StartedAt:        startedAt,
		Options:          options,
	}
	state := cloneValidatorState(a.validatorState)
	a.validatorMu.Unlock()
	a.emit("validator:state", state)
	_ = writeValidatorResultMetadata(state.ResultsFilePath, state)
	a.logValidatorStart(state)

	return state, ctx, runID, nil
}

func (a *App) CancelValidatorScan() (model.ValidatorState, error) {
	a.validatorMu.Lock()
	if a.validatorCancel != nil {
		a.validatorCancel()
		a.validatorCancel = nil
	}
	if a.validatorState.Status == model.ValidatorRunning {
		a.validatorState.Status = model.ValidatorCancelled
		a.validatorState.Paused = false
		a.validatorState.FinishedAt = time.Now().UnixMilli()
	}
	pending := a.takeValidatorPendingResultsLocked()
	state := cloneValidatorProgressState(a.validatorState)
	response := cloneValidatorStateWithoutResults(a.validatorState)
	a.validatorMu.Unlock()
	a.emitValidatorProgress(state, pending)
	return response, nil
}

func (a *App) SetValidatorPaused(paused bool) (model.ValidatorState, error) {
	a.validatorMu.Lock()
	if a.validatorState.Status != model.ValidatorRunning {
		state := cloneValidatorState(a.validatorState)
		a.validatorMu.Unlock()
		return state, fmt.Errorf("validator is not running")
	}
	a.validatorState.Paused = paused
	pending := a.takeValidatorPendingResultsLocked()
	state := cloneValidatorProgressState(a.validatorState)
	response := cloneValidatorStateWithoutResults(a.validatorState)
	a.validatorMu.Unlock()
	a.emitValidatorProgress(state, pending)
	return response, nil
}

func (a *App) ClearValidatorResults() (model.ValidatorState, error) {
	a.validatorMu.Lock()
	if a.validatorState.Status == model.ValidatorRunning || a.validatorResultWriter != nil {
		state := cloneValidatorState(a.validatorState)
		a.validatorMu.Unlock()
		return state, fmt.Errorf("cancel the active scan before clearing results")
	}
	a.validatorState = model.ValidatorState{Status: model.ValidatorIdle, Results: []model.ValidatorResult{}}
	a.validatorPendingResults = nil
	state := cloneValidatorState(a.validatorState)
	a.validatorMu.Unlock()
	a.emit("validator:state", state)
	return state, nil
}

func (a *App) runValidatorBatch(ctx context.Context, runID int64, endpoints []model.ValidatorEndpointInput, options model.ValidatorOptions) {
	err := a.runValidatorRequests(ctx, runID, options, func(jobs chan<- model.ValidatorEndpointInput) error {
		for _, endpoint := range endpoints {
			if !a.sendValidatorJob(ctx, runID, jobs, endpoint) {
				if err := ctx.Err(); err != nil {
					return err
				}
				return context.Canceled
			}
		}
		return nil
	})
	a.finishValidatorRun(runID, err)
}

func (a *App) runValidatorRangeBatch(ctx context.Context, runID int64, ranges []string, ports []int, sni string, options model.ValidatorOptions) {
	normalizedSNI := strings.TrimSpace(sni)
	err := a.runValidatorRequests(ctx, runID, options, func(jobs chan<- model.ValidatorEndpointInput) error {
		for _, value := range ranges {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("invalid IPv4 range %q", value)
			}
			first, last := validatorHostRange(prefix.Masked())
			if !first.IsValid() || !last.IsValid() {
				return fmt.Errorf("IPv4 range %s is invalid", prefix.Masked().String())
			}
			for addr := first; ; addr = addr.Next() {
				host := addr.Unmap().String()
				for _, port := range ports {
					if !a.sendValidatorJob(ctx, runID, jobs, model.ValidatorEndpointInput{
						Host: host,
						Port: port,
						SNI:  normalizedSNI,
					}) {
						if err := ctx.Err(); err != nil {
							return err
						}
						return context.Canceled
					}
				}
				if addr == last {
					break
				}
			}
		}
		return nil
	})
	a.finishValidatorRun(runID, err)
}

func (a *App) finishValidatorRun(runID int64, err error) {
	a.validatorMu.Lock()
	if a.validatorRunID != runID {
		a.validatorMu.Unlock()
		return
	}
	if a.validatorCancel != nil {
		a.validatorCancel = nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		if a.validatorState.Status == model.ValidatorRunning {
			a.validatorState.Status = model.ValidatorCancelled
			a.validatorState.Paused = false
			a.validatorState.FinishedAt = time.Now().UnixMilli()
		}
	case err != nil:
		a.validatorState.Status = model.ValidatorFailed
		a.validatorState.Paused = false
		a.validatorState.Error = err.Error()
		a.validatorState.FinishedAt = time.Now().UnixMilli()
	default:
		if a.validatorState.Status == model.ValidatorRunning {
			a.validatorState.Status = model.ValidatorCompleted
			a.validatorState.Paused = false
			a.validatorState.Completed = a.validatorState.Total
			a.validatorState.FinishedAt = time.Now().UnixMilli()
		}
	}
	writer := a.validatorResultWriter
	a.validatorMu.Unlock()

	var rows int
	var closeErr error
	if writer != nil {
		rows, closeErr = writer.Close()
	}

	var metaState model.ValidatorState
	a.validatorMu.Lock()
	if a.validatorRunID != runID {
		a.validatorMu.Unlock()
		return
	}
	if a.validatorResultWriter == writer {
		a.validatorResultWriter = nil
	}
	if writer != nil {
		a.validatorState.ResultsFileRows = rows
	}
	if closeErr != nil && a.validatorState.Status != model.ValidatorCancelled {
		a.validatorState.Status = model.ValidatorFailed
		a.validatorState.Paused = false
		a.validatorState.Error = closeErr.Error()
		a.validatorState.FinishedAt = time.Now().UnixMilli()
	}
	pending := a.takeValidatorPendingResultsLocked()
	state := cloneValidatorProgressState(a.validatorState)
	metaState = cloneValidatorState(a.validatorState)
	done := a.validatorDone
	a.validatorDone = nil
	a.validatorMu.Unlock()
	if metaState.ResultsFilePath != "" {
		_ = writeValidatorResultMetadata(metaState.ResultsFilePath, metaState)
	}
	a.emitValidatorProgress(state, pending)
	if done != nil {
		close(done)
	}
}

func (a *App) waitValidatorStopped(timeout time.Duration) {
	a.validatorMu.Lock()
	done := a.validatorDone
	active := a.validatorState.Status == model.ValidatorRunning || a.validatorResultWriter != nil
	a.validatorMu.Unlock()
	if !active || done == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		a.handleLog("Validator shutdown warning: timed out waiting for CSV finalization")
	}
}

func validatorScanRequest(endpoint model.ValidatorEndpointInput, options model.ValidatorOptions) tunnelengine.ScanRequest {
	return tunnelengine.ScanRequest{
		Host:              endpoint.Host,
		Port:              endpoint.Port,
		TimeoutMillis:     options.TimeoutMillis,
		Retries:           options.Retries,
		SNI:               endpoint.SNI,
		HTTPPaths:         options.HTTPPaths,
		DNSQuestion:       options.DNSQuestion,
		EnableUDP:         options.EnableUDP,
		EnableQUIC:        options.EnableQUIC,
		EnableDNS:         options.EnableDNS,
		EnableWebSocket:   options.EnableWebSocket,
		AllowInsecureCert: options.AllowInsecureCert,
	}
}

func (a *App) runValidatorRequests(ctx context.Context, runID int64, options model.ValidatorOptions, feed func(chan<- model.ValidatorEndpointInput) error) error {
	controller := newValidatorWorkerController(newValidatorWorkerPlan(options))
	workerCount := controller.workerCount()
	jobs := make(chan model.ValidatorEndpointInput, workerCount*2)
	var wg sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					a.failValidatorRun(runID, fmt.Errorf("validator worker panic: %v", recovered))
				}
			}()
			for endpoint := range jobs {
				if !a.waitValidatorResume(ctx, runID) {
					return
				}
				if !a.processValidatorEndpoint(ctx, runID, endpoint, options, controller) {
					return
				}
			}
		}()
	}

	err := feed(jobs)
	close(jobs)
	wg.Wait()
	if err != nil {
		return err
	}
	return ctx.Err()
}

func (a *App) processValidatorEndpoint(ctx context.Context, runID int64, endpoint model.ValidatorEndpointInput, options model.ValidatorOptions, controller *validatorWorkerController) (ok bool) {
	acquired := false
	defer func() {
		if recovered := recover(); recovered != nil {
			if acquired {
				snapshot, changed := controller.release(false)
				if changed {
					a.updateValidatorWorkerStats(runID, snapshot)
				}
			}
			a.failValidatorRun(runID, fmt.Errorf("validator endpoint panic: %v", recovered))
			ok = false
		}
	}()
	if !controller.acquire(ctx) {
		return false
	}
	acquired = true
	request := validatorScanRequest(endpoint, options)
	result := tunnelengine.ScanEndpointWithContext(ctx, request)
	pressure := validatorScanResultHasPressure(result)
	snapshot, changed := controller.release(pressure)
	acquired = false
	if changed {
		a.updateValidatorWorkerStats(runID, snapshot)
	}
	a.recordValidatorResult(ctx, runID, result, options, endpoint.SNI)
	return ctx.Err() == nil
}

type validatorWorkerPlan struct {
	requested int
	ceiling   int
	effective int
	adaptive  bool
}

type validatorWorkerSnapshot struct {
	requested      int
	ceiling        int
	effective      int
	pressureEvents int
}

type validatorWorkerController struct {
	mu                   sync.Mutex
	requested            int
	ceiling              int
	effective            int
	active               int
	adaptive             bool
	pressureEvents       int
	successesSinceChange int
}

func newValidatorWorkerPlan(options model.ValidatorOptions) validatorWorkerPlan {
	return newValidatorWorkerPlanForOS(runtime.GOOS, options)
}

func newValidatorWorkerPlanForOS(goos string, options model.ValidatorOptions) validatorWorkerPlan {
	requested := options.WorkerCount
	if requested <= 0 {
		requested = defaultValidatorWorkerCount
	}
	if requested > maxValidatorWorkerCount {
		requested = maxValidatorWorkerCount
	}
	ceiling := requested
	effective := requested
	adaptive := false
	if goos == "windows" {
		adaptive = true
		ceiling = minInt(requested, windowsValidatorWorkerCeiling(options))
		effective = minInt(ceiling, defaultValidatorWorkerCount)
	}
	if ceiling < 1 {
		ceiling = 1
	}
	if effective < 1 {
		effective = 1
	}
	return validatorWorkerPlan{requested: requested, ceiling: ceiling, effective: effective, adaptive: adaptive}
}

func windowsValidatorWorkerCeiling(options model.ValidatorOptions) int {
	pressure := 3 // TCP, TLS and HTTP are part of the base probe.
	if options.EnableWebSocket {
		pressure++
	}
	if options.EnableUDP {
		pressure++
	}
	if options.EnableQUIC {
		pressure += 2
	}
	if options.EnableDNS {
		pressure += 2
	}
	switch {
	case pressure >= 8:
		return 150
	case pressure >= 6:
		return 192
	case pressure >= 4:
		return 256
	default:
		return 512
	}
}

func newValidatorWorkerController(plan validatorWorkerPlan) *validatorWorkerController {
	return &validatorWorkerController{
		requested: plan.requested,
		ceiling:   plan.ceiling,
		effective: plan.effective,
		adaptive:  plan.adaptive,
	}
}

func (c *validatorWorkerController) workerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ceiling
}

func (c *validatorWorkerController) acquire(ctx context.Context) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		c.mu.Lock()
		if c.active < c.effective {
			c.active++
			c.mu.Unlock()
			return true
		}
		c.mu.Unlock()
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false
		case <-timer.C:
		}
	}
}

func (c *validatorWorkerController) release(pressure bool) (validatorWorkerSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active > 0 {
		c.active--
	}
	changed := false
	if c.adaptive && pressure {
		c.pressureEvents++
		c.successesSinceChange = 0
		next := maxInt(1, (c.effective*3)/4)
		if next < c.effective {
			c.effective = next
			changed = true
		}
	} else if c.adaptive && c.effective < c.ceiling {
		c.successesSinceChange++
		threshold := maxInt(100, c.effective*4)
		if c.successesSinceChange >= threshold {
			increment := maxInt(1, c.ceiling/16)
			next := minInt(c.ceiling, c.effective+increment)
			if next > c.effective {
				c.effective = next
				changed = true
			}
			c.successesSinceChange = 0
		}
	}
	return validatorWorkerSnapshot{
		requested:      c.requested,
		ceiling:        c.ceiling,
		effective:      c.effective,
		pressureEvents: c.pressureEvents,
	}, changed
}

func (a *App) updateValidatorWorkerStats(runID int64, snapshot validatorWorkerSnapshot) {
	a.validatorMu.Lock()
	if a.validatorRunID == runID && a.validatorState.Status == model.ValidatorRunning {
		a.validatorState.RequestedWorkers = snapshot.requested
		a.validatorState.WorkerCeiling = snapshot.ceiling
		a.validatorState.EffectiveWorkers = snapshot.effective
		a.validatorState.PressureEvents = snapshot.pressureEvents
	}
	a.validatorMu.Unlock()
}

func validatorScanResultHasPressure(result tunnelengine.ScanResult) bool {
	for _, errText := range result.Errors {
		if validatorErrorTextHasPressure(errText) {
			return true
		}
	}
	for _, attempt := range result.TCP.Attempts {
		if validatorErrorTextHasPressure(attempt.ErrorCategory) {
			return true
		}
	}
	if validatorErrorTextHasPressure(result.TLS.ErrorCategory) || validatorErrorTextHasPressure(result.WebSocket.ErrorCategory) ||
		validatorErrorTextHasPressure(result.UDP.ErrorCategory) || validatorErrorTextHasPressure(result.QUIC.ErrorCategory) ||
		validatorErrorTextHasPressure(result.DNS.ErrorCategory) {
		return true
	}
	for _, probe := range result.HTTP.Probes {
		if validatorErrorTextHasPressure(probe.ErrorCategory) {
			return true
		}
	}
	for _, attempt := range result.UDP.Attempts {
		if validatorErrorTextHasPressure(attempt.ErrorCategory) {
			return true
		}
	}
	for _, attempt := range result.DNS.Attempts {
		if validatorErrorTextHasPressure(attempt.ErrorCategory) {
			return true
		}
	}
	return false
}

func validatorErrorTextHasPressure(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	if value == "socket_pressure" || value == "resource_pressure" {
		return true
	}
	return strings.Contains(value, "too many open files") ||
		strings.Contains(value, "too many open connections") ||
		strings.Contains(value, "cannot assign requested address") ||
		strings.Contains(value, "address already in use") ||
		strings.Contains(value, "only one usage of each socket address") ||
		strings.Contains(value, "lacked sufficient buffer space") ||
		strings.Contains(value, "no buffer space available")
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (a *App) sendValidatorJob(ctx context.Context, runID int64, jobs chan<- model.ValidatorEndpointInput, endpoint model.ValidatorEndpointInput) bool {
	if !a.waitValidatorResume(ctx, runID) {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case jobs <- endpoint:
		return true
	}
}

func (a *App) waitValidatorResume(ctx context.Context, runID int64) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		a.validatorMu.Lock()
		active := a.validatorRunID == runID && a.validatorState.Status == model.ValidatorRunning
		paused := active && a.validatorState.Paused
		a.validatorMu.Unlock()
		if !active {
			return false
		}
		if !paused {
			return true
		}
		timer := time.NewTimer(150 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return false
		case <-timer.C:
		}
	}
}

func (a *App) recordValidatorResult(ctx context.Context, runID int64, result tunnelengine.ScanResult, options model.ValidatorOptions, sni string) {
	wroteCSV, err := a.writeValidatorCSVResult(ctx, runID, result, sni)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		a.failValidatorRun(runID, fmt.Errorf("validator CSV write failed: %w", err))
		return
	}
	a.validatorMu.Lock()
	if a.validatorRunID != runID || a.validatorState.Status != model.ValidatorRunning {
		a.validatorMu.Unlock()
		return
	}
	a.validatorState.Completed++
	if wroteCSV {
		a.validatorState.ResultsFileRows++
		a.validatorState.Retained++
	}
	a.recordValidatorGradeLocked(result.Score.Grade)
	if validatorScanResultIsReady(result) {
		a.validatorState.Ready++
	}
	if result.Score.Numeric > a.validatorState.BestScore {
		a.validatorState.BestScore = result.Score.Numeric
	}
	now := time.Now()
	shouldEmit := a.validatorState.Completed >= a.validatorState.Total || now.Sub(a.validatorLastEmit) >= validatorStateEmitInterval
	shouldWriteMeta := a.validatorState.ResultsFilePath != "" &&
		(a.validatorState.Completed%validatorResultMetaRowInterval == 0 || now.Sub(a.validatorLastMetadataWrite) >= validatorResultMetaInterval || a.validatorState.Completed >= a.validatorState.Total)
	shouldLogDiagnostics := a.validatorState.Completed > 0 && a.validatorState.Completed%validatorResultMetaRowInterval == 0
	var pending []model.ValidatorResult
	var state validatorProgressEvent
	var metaState model.ValidatorState
	var diagnosticLine string
	if shouldEmit {
		a.validatorLastEmit = now
		pending = a.takeValidatorPendingResultsLocked()
		state = cloneValidatorProgressState(a.validatorState)
	}
	if shouldWriteMeta {
		a.validatorLastMetadataWrite = now
		metaState = cloneValidatorStateWithoutResults(a.validatorState)
	}
	if shouldLogDiagnostics {
		diagnosticLine = validatorDiagnosticsLine(a.validatorState)
	}
	a.validatorMu.Unlock()
	if shouldWriteMeta {
		if err := writeValidatorResultMetadata(metaState.ResultsFilePath, metaState); err != nil {
			a.handleLog("Validator metadata warning: " + err.Error())
		}
	}
	if diagnosticLine != "" {
		a.handleLog(diagnosticLine)
	}
	if shouldEmit {
		a.emitValidatorProgress(state, pending)
	}
}

func (a *App) recordValidatorGradeLocked(grade string) {
	switch strings.ToUpper(strings.TrimSpace(grade)) {
	case "A+":
		a.validatorState.GradeAPlus++
	case "A":
		a.validatorState.GradeA++
	case "B":
		a.validatorState.GradeB++
	case "C":
		a.validatorState.GradeC++
	case "F":
		a.validatorState.GradeF++
	}
}

func validatorScanResultIsReady(result tunnelengine.ScanResult) bool {
	return strings.EqualFold(strings.TrimSpace(result.Score.Classification), "Tunnel Ready")
}

func normalizeValidatorRequest(request model.ValidatorRequest) ([]model.ValidatorEndpointInput, model.ValidatorOptions, error) {
	options := normalizeValidatorOptions(request.Options)
	endpoints := make([]model.ValidatorEndpointInput, 0, len(request.Endpoints))
	for _, endpoint := range request.Endpoints {
		host := strings.TrimSpace(strings.TrimSuffix(endpoint.Host, "."))
		sni := strings.TrimSpace(endpoint.SNI)
		port := endpoint.Port
		if host == "" {
			return nil, options, fmt.Errorf("validator endpoint host is required")
		}
		if port == 0 {
			port = defaultValidatorPort
		}
		if port < 1 || port > 65535 {
			return nil, options, fmt.Errorf("validator endpoint %s has invalid port %d", host, endpoint.Port)
		}
		endpoints = append(endpoints, model.ValidatorEndpointInput{
			Host: host,
			Port: port,
			SNI:  sni,
		})
	}
	if len(endpoints) == 0 {
		return nil, options, fmt.Errorf("add at least one endpoint to scan")
	}
	return endpoints, options, nil
}

func normalizeValidatorOptions(options model.ValidatorOptions) model.ValidatorOptions {
	if options.Retries < 1 {
		options.Retries = 1
	}
	if options.Retries > 8 {
		options.Retries = 8
	}
	if options.TimeoutMillis < 250 {
		options.TimeoutMillis = 600
	}
	if options.TimeoutMillis > 60000 {
		options.TimeoutMillis = 60000
	}
	workerCount := options.WorkerCount
	if workerCount < 1 {
		workerCount = options.AdaptiveLimit
	}
	if workerCount < 1 {
		workerCount = defaultValidatorWorkerCount
	}
	if workerCount > maxValidatorWorkerCount {
		workerCount = maxValidatorWorkerCount
	}
	options.WorkerCount = workerCount
	options.AdaptiveLimit = workerCount
	if len(options.HTTPPaths) == 0 {
		options.HTTPPaths = []string{"/"}
	}
	if strings.TrimSpace(options.DNSQuestion) == "" {
		options.DNSQuestion = "cloudflare.com."
	}
	return options
}

func readDefaultValidatorRangeCSV() ([]byte, error) {
	for _, candidate := range defaultValidatorRangeCandidates() {
		raw, err := os.ReadFile(candidate)
		if err == nil {
			return raw, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	raw, err := defaultIPv4RangeAssets.ReadFile(defaultValidatorRangeCSVName)
	if err == nil {
		return raw, nil
	}
	return nil, fmt.Errorf("%s is unavailable", defaultValidatorRangeCSVName)
}

func defaultValidatorRangeCandidates() []string {
	candidates := make([]string, 0)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, defaultValidatorRangeCSVName),
			filepath.Join(cwd, "desktop", defaultValidatorRangeCSVName),
			filepath.Join(cwd, "..", defaultValidatorRangeCSVName),
			filepath.Join(cwd, "..", "desktop", defaultValidatorRangeCSVName),
		)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, defaultValidatorRangeCSVName),
			filepath.Join(dir, "Resources", defaultValidatorRangeCSVName),
			filepath.Join(dir, "..", "Resources", defaultValidatorRangeCSVName),
			filepath.Join(dir, "..", "..", "Resources", defaultValidatorRangeCSVName),
		)
	}
	return candidates
}

func parseValidatorRangeOptions(raw []byte) ([]model.ValidatorRangeOption, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s must contain a network column", defaultValidatorRangeCSVName)
	}
	if err != nil {
		return nil, err
	}
	networkColumn := validatorCSVNetworkColumn(header)
	if networkColumn < 0 {
		return nil, fmt.Errorf("%s must contain a network column", defaultValidatorRangeCSVName)
	}
	seen := map[string]struct{}{}
	options := make([]model.ValidatorRangeOption, 0)
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if networkColumn >= len(record) {
			continue
		}
		value := record[networkColumn]
		network := strings.TrimSpace(value)
		if network == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(network)
		if err != nil || !prefix.Addr().Unmap().Is4() {
			continue
		}
		prefix = prefix.Masked()
		normalized := prefix.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		hostCount, ok := validatorUsableHostCount(prefix)
		if !ok {
			hostCount = 0
		}
		options = append(options, model.ValidatorRangeOption{
			Range:     normalized,
			HostCount: hostCount,
		})
	}
	if len(options) == 0 {
		return nil, fmt.Errorf("%s contains no IPv4 ranges", defaultValidatorRangeCSVName)
	}
	return options, nil
}

func parseValidatorRangeImportInput(rawText string) model.ValidatorRangeImportResult {
	values := validatorRangeImportValues(rawText)
	result := model.ValidatorRangeImportResult{
		Ranges: make([]model.ValidatorRangeOption, 0, len(values)),
	}
	seen := map[string]struct{}{}
	for _, raw := range values {
		value := cleanValidatorRangeToken(raw)
		if value == "" {
			continue
		}
		result.TotalCount++
		option, ok := validatorRangeOptionFromValue(value)
		if !ok {
			result.InvalidCount++
			if len(result.Invalid) < validatorImportInvalidSampleMax {
				result.Invalid = append(result.Invalid, value)
			}
			continue
		}
		if _, exists := seen[option.Range]; exists {
			result.DuplicateCount++
			continue
		}
		seen[option.Range] = struct{}{}
		result.Ranges = append(result.Ranges, option)
	}
	return result
}

func validatorRangeImportValues(rawText string) []string {
	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return nil
	}
	reader := csv.NewReader(strings.NewReader(trimmed))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	header, err := reader.Read()
	if err == nil {
		if networkColumn := validatorCSVNetworkColumn(header); networkColumn >= 0 {
			values := make([]string, 0)
			for {
				record, readErr := reader.Read()
				if errors.Is(readErr, io.EOF) {
					break
				}
				if readErr != nil {
					break
				}
				if networkColumn < len(record) {
					values = append(values, record[networkColumn])
				}
			}
			return values
		}
	}
	return strings.FieldsFunc(rawText, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
}

func validatorRangeOptionFromValue(value string) (model.ValidatorRangeOption, bool) {
	prefix, ok := parseValidatorRangePrefix(value)
	if !ok {
		return model.ValidatorRangeOption{}, false
	}
	hostCount, hostOK := validatorUsableHostCount(prefix)
	if !hostOK || hostCount <= 0 || hostCount > maxValidatorRangeHosts {
		return model.ValidatorRangeOption{}, false
	}
	return model.ValidatorRangeOption{
		Range:     prefix.String(),
		HostCount: hostCount,
	}, true
}

func parseValidatorRangePrefix(value string) (netip.Prefix, bool) {
	value = cleanValidatorRangeToken(value)
	if value == "" {
		return netip.Prefix{}, false
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		addr := prefix.Addr().Unmap()
		if !addr.Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, prefix.Bits()).Masked(), true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, 32), true
}

func cleanValidatorRangeToken(value string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	trimmed = strings.Trim(trimmed, `"'`)
	return strings.TrimSpace(trimmed)
}

func validatorCSVNetworkColumn(header []string) int {
	for idx, value := range header {
		normalized := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "\ufeff")))
		switch normalized {
		case "network", "range", "cidr", "ipv4", "ipv4_range":
			return idx
		}
	}
	return -1
}

func normalizeValidatorRangeSelection(ranges []string) ([]string, error) {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(ranges))
	totalHosts := 0
	for _, raw := range ranges {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		prefix, ok := parseValidatorRangePrefix(value)
		if !ok {
			return nil, fmt.Errorf("invalid IPv4 range %q", value)
		}
		hostCount, ok := validatorUsableHostCount(prefix)
		if !ok || hostCount <= 0 || hostCount > maxValidatorRangeHosts {
			return nil, fmt.Errorf("IPv4 range %s is too large to validate", prefix.String())
		}
		value = prefix.String()
		if _, exists := seen[value]; exists {
			continue
		}
		if totalHosts+hostCount > maxValidatorRangeSelectionHosts {
			return nil, fmt.Errorf("selected IPv4 ranges contain more than %d endpoints; select fewer ranges", maxValidatorRangeSelectionHosts)
		}
		seen[value] = struct{}{}
		totalHosts += hostCount
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("select at least one IPv4 range to validate")
	}
	return normalized, nil
}

func normalizeValidatorRangePorts(ports []int, legacyPort int) ([]int, error) {
	if len(ports) == 0 && legacyPort != 0 {
		ports = []int{legacyPort}
	}
	if len(ports) == 0 {
		ports = []int{defaultValidatorPort}
	}
	seen := map[int]struct{}{}
	normalized := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("validator range port must be between 1 and 65535")
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		normalized = append(normalized, port)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("select at least one validator port")
	}
	return normalized, nil
}

func validatorRangeEndpointCount(ranges []string, ports []int) (int, error) {
	if len(ports) == 0 {
		return 0, fmt.Errorf("select at least one validator port")
	}
	total := 0
	for _, value := range ranges {
		prefix, ok := parseValidatorRangePrefix(value)
		if !ok {
			return 0, fmt.Errorf("invalid IPv4 range %q", value)
		}
		count, ok := validatorUsableHostCount(prefix)
		if !ok || count <= 0 || count > maxValidatorRangeHosts {
			return 0, fmt.Errorf("IPv4 range %s is too large to validate", prefix.String())
		}
		endpointCount := count * len(ports)
		if total+endpointCount > maxValidatorRangeSelectionHosts {
			return 0, fmt.Errorf("selected IPv4 ranges contain more than %d endpoints; select fewer ranges", maxValidatorRangeSelectionHosts)
		}
		total += endpointCount
	}
	if total == 0 {
		return 0, fmt.Errorf("select at least one IPv4 range to validate")
	}
	return total, nil
}

func validatorPortsFromEndpoints(endpoints []model.ValidatorEndpointInput) []int {
	seen := map[int]struct{}{}
	ports := make([]int, 0)
	for _, endpoint := range endpoints {
		port := endpoint.Port
		if port == 0 {
			port = defaultValidatorPort
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports
}

func validatorEndpointsFromRanges(ranges []string, ports []int, sni string) ([]model.ValidatorEndpointInput, error) {
	ports, err := normalizeValidatorRangePorts(ports, 0)
	if err != nil {
		return nil, err
	}
	if _, err := validatorRangeEndpointCount(ranges, ports); err != nil {
		return nil, err
	}
	endpoints := make([]model.ValidatorEndpointInput, 0)
	for _, value := range ranges {
		prefix, ok := parseValidatorRangePrefix(value)
		if !ok {
			return nil, fmt.Errorf("invalid IPv4 range %q", value)
		}
		count, ok := validatorUsableHostCount(prefix)
		if !ok || count <= 0 || count > maxValidatorRangeHosts {
			return nil, fmt.Errorf("IPv4 range %s is too large to validate", prefix.String())
		}
		first, last := validatorHostRange(prefix)
		if !first.IsValid() || !last.IsValid() {
			return nil, fmt.Errorf("IPv4 range %s is invalid", prefix.String())
		}
		endpointCount := count * len(ports)
		if len(endpoints)+endpointCount > maxValidatorRangeSelectionHosts {
			return nil, fmt.Errorf("selected IPv4 ranges contain more than %d endpoints; select fewer ranges", maxValidatorRangeSelectionHosts)
		}
		for addr := first; ; addr = addr.Next() {
			for _, port := range ports {
				endpoints = append(endpoints, model.ValidatorEndpointInput{
					Host: addr.Unmap().String(),
					Port: port,
					SNI:  strings.TrimSpace(sni),
				})
			}
			if addr == last {
				break
			}
		}
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("select at least one IPv4 range to validate")
	}
	return endpoints, nil
}

func validatorUsableHostCount(prefix netip.Prefix) (int, bool) {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if !addr.Is4() {
		return 0, false
	}
	hostBits := 32 - prefix.Bits()
	switch {
	case hostBits == 0:
		return 1, true
	case hostBits == 1:
		return 2, true
	case hostBits > 31:
		return 0, false
	default:
		return (1 << hostBits) - 2, true
	}
}

func validatorHostRange(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	network := prefix.Addr().Unmap()
	last := validatorPrefixLastAddr(prefix)
	if network.Is4() && prefix.Bits() < 31 {
		return network.Next(), validatorPrevAddr(last)
	}
	return network, last
}

func validatorPrefixLastAddr(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	b := addr.As4()
	hostBits := 32 - prefix.Bits()
	value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if hostBits > 0 {
		value |= (uint32(1) << hostBits) - 1
	}
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func validatorPrevAddr(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}
	b := addr.As4()
	value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if value == 0 {
		return addr
	}
	value--
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func convertValidatorResult(result tunnelengine.ScanResult) model.ValidatorResult {
	return model.ValidatorResult{
		Endpoint:       result.Endpoint,
		Host:           result.Host,
		Port:           result.Port,
		TCP:            result.TCP.Success,
		TLS:            result.TLS.Success,
		HTTP:           result.HTTP.Success,
		WebSocket:      result.WebSocket.Success,
		UDP:            result.UDP.Reachable,
		QUIC:           result.QUIC.Success,
		DNS:            result.DNS.UDPResponsive || result.DNS.TCPResponsive,
		RTTMs:          result.Metrics.RTTMs,
		JitterMs:       result.Metrics.JitterMs,
		PacketLoss:     result.Metrics.PacketLossEstimate,
		Stability:      result.Metrics.StabilityPercent,
		Score:          result.Score.Numeric,
		Grade:          result.Score.Grade,
		Classification: result.Score.Classification,
		Confidence:     result.Score.Confidence,
		FalsePositive:  result.Score.FalsePositive,
		Reasons:        append([]string(nil), result.Score.Reasons...),
		Errors:         append([]string(nil), result.Errors...),
	}
}

func cloneValidatorState(state model.ValidatorState) model.ValidatorState {
	state.Results = cloneValidatorResults(state.Results)
	state.Ports = append([]int(nil), state.Ports...)
	state.Options.HTTPPaths = append([]string(nil), state.Options.HTTPPaths...)
	return state
}

func cloneValidatorStateWithoutResults(state model.ValidatorState) model.ValidatorState {
	state.Results = nil
	state.Ports = append([]int(nil), state.Ports...)
	state.Options.HTTPPaths = append([]string(nil), state.Options.HTTPPaths...)
	return state
}

func cloneValidatorProgressState(state model.ValidatorState) validatorProgressEvent {
	return validatorProgressEvent{
		Status:           state.Status,
		Paused:           state.Paused,
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
		Ports:            append([]int(nil), state.Ports...),
		ResultsFileName:  state.ResultsFileName,
		ResultsFilePath:  state.ResultsFilePath,
		ResultsFileRows:  state.ResultsFileRows,
		ResultsFilePart:  state.ResultsFilePart,
		ResultsFileCount: state.ResultsFileCount,
		RequestedWorkers: state.RequestedWorkers,
		EffectiveWorkers: state.EffectiveWorkers,
		WorkerCeiling:    state.WorkerCeiling,
		PressureEvents:   state.PressureEvents,
		Error:            state.Error,
		StartedAt:        state.StartedAt,
		FinishedAt:       state.FinishedAt,
		Options: model.ValidatorOptions{
			Retries:           state.Options.Retries,
			TimeoutMillis:     state.Options.TimeoutMillis,
			WorkerCount:       state.Options.WorkerCount,
			AdaptiveLimit:     state.Options.AdaptiveLimit,
			HTTPPaths:         append([]string(nil), state.Options.HTTPPaths...),
			DNSQuestion:       state.Options.DNSQuestion,
			EnableUDP:         state.Options.EnableUDP,
			EnableQUIC:        state.Options.EnableQUIC,
			EnableDNS:         state.Options.EnableDNS,
			EnableWebSocket:   state.Options.EnableWebSocket,
			AllowInsecureCert: state.Options.AllowInsecureCert,
		},
	}
}

func cloneValidatorResults(results []model.ValidatorResult) []model.ValidatorResult {
	if results == nil {
		return nil
	}
	cloned := make([]model.ValidatorResult, len(results))
	copy(cloned, results)
	for idx := range cloned {
		cloned[idx].Reasons = append([]string(nil), cloned[idx].Reasons...)
		cloned[idx].Errors = append([]string(nil), cloned[idx].Errors...)
	}
	return cloned
}

func (a *App) logValidatorStart(state model.ValidatorState) {
	a.handleLog(fmt.Sprintf(
		"Validator started: os=%s mode=%s total=%d ports=%v requested_workers=%d effective_workers=%d worker_ceiling=%d timeout_ms=%d retries=%d udp=%t quic=%t dns=%t websocket=%t csv=%s",
		runtime.GOOS,
		state.Mode,
		state.Total,
		state.Ports,
		state.RequestedWorkers,
		state.EffectiveWorkers,
		state.WorkerCeiling,
		state.Options.TimeoutMillis,
		state.Options.Retries,
		state.Options.EnableUDP,
		state.Options.EnableQUIC,
		state.Options.EnableDNS,
		state.Options.EnableWebSocket,
		state.ResultsFileName,
	))
}

func validatorDiagnosticsLine(state model.ValidatorState) string {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	handleCount := validatorProcessHandleCount()
	handleText := ""
	if handleCount > 0 {
		handleText = fmt.Sprintf(" handles=%d", handleCount)
	}
	return fmt.Sprintf(
		"Validator diagnostics: completed=%d total=%d csv_rows=%d csv=%s goroutines=%d heap_mb=%d sys_mb=%d requested_workers=%d effective_workers=%d worker_ceiling=%d pressure_events=%d%s",
		state.Completed,
		state.Total,
		state.ResultsFileRows,
		state.ResultsFileName,
		runtime.NumGoroutine(),
		mem.HeapAlloc/1024/1024,
		mem.Sys/1024/1024,
		state.RequestedWorkers,
		state.EffectiveWorkers,
		state.WorkerCeiling,
		state.PressureEvents,
		handleText,
	)
}

func (a *App) takeValidatorPendingResultsLocked() []model.ValidatorResult {
	pending := a.validatorPendingResults
	a.validatorPendingResults = nil
	if len(pending) > validatorUIResultLimit {
		pending = pending[len(pending)-validatorUIResultLimit:]
	}
	return pending
}

func (a *App) emitValidatorProgress(state validatorProgressEvent, pending []model.ValidatorResult) {
	if len(pending) > 0 {
		state.Results = pending
		state.AppendResults = true
	}
	a.emit("validator:progress", state)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
