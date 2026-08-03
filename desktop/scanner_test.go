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
	"whitevpn-desktop/internal/profiles"
	"whitevpn-desktop/internal/storm"
)

func TestScannerInputParsesPortsCIDRsInvalidAndDuplicates(t *testing.T) {
	raw := []string{
		"1.1.1.1:5353, 8.8.8.8",
		"192.0.2.0/30",
		"192.0.2.1",
		"bad-entry",
	}
	seen := map[string]struct{}{}
	var resolvers []string
	invalid := 0
	duplicates := 0
	for _, line := range raw {
		for _, token := range scannerInputTokens(line) {
			parsed, ok := scannerResolversFromToken(token)
			if !ok {
				invalid++
				continue
			}
			for _, resolver := range parsed {
				if _, exists := seen[resolver]; exists {
					duplicates++
					continue
				}
				seen[resolver] = struct{}{}
				resolvers = append(resolvers, resolver)
			}
		}
	}

	want := []string{"1.1.1.1", "8.8.8.8", "192.0.2.1", "192.0.2.2"}
	if !reflect.DeepEqual(resolvers, want) {
		t.Fatalf("unexpected normalized resolvers: got %#v want %#v", resolvers, want)
	}
	if invalid != 1 || duplicates != 1 {
		t.Fatalf("unexpected skip counts: invalid=%d duplicates=%d", invalid, duplicates)
	}
}

func TestScannerInputRejectsTooLargeRangeAndAcceptsSlash32(t *testing.T) {
	if _, ok := scannerResolversFromToken("10.0.0.0/8"); ok {
		t.Fatal("expected /8 to be rejected")
	}
	resolvers, ok := scannerResolversFromToken("203.0.113.7/32:53")
	if !ok || len(resolvers) != 1 || resolvers[0] != "203.0.113.7" {
		t.Fatalf("expected /32 with ignored port to normalize, got %#v ok=%t", resolvers, ok)
	}
}

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

func TestRenderScannerClientTOMLUsesScannerDefaultsAndDynamicFields(t *testing.T) {
	connection := model.ConnectionProfile{
		Domain:           "scan.example.com.",
		EncryptionKey:    `abc"123`,
		EncryptionMethod: 2,
	}
	toml := storm.RenderScannerClientTOML(connection, 23001, 23002, 9999)
	for _, line := range []string{
		`# WHITEDNS_IMPORT_TYPE = "masterdns"`,
		`DOMAINS = ["scan.example.com"]`,
		`DATA_ENCRYPTION_METHOD = 2`,
		`ENCRYPTION_KEY = "abc\"123"`,
		`LISTEN_PORT = 23001`,
		`PACKET_DUPLICATION_COUNT = 1`,
		`MTU_TEST_PARALLELISM = 1000`,
		`MIN_UPLOAD_MTU = 30`,
		`MAX_DOWNLOAD_MTU = 40`,
	} {
		if !strings.Contains(toml, line) {
			t.Fatalf("scanner TOML missing %q:\n%s", line, toml)
		}
	}
}

func TestRenderConnectionUpgradeScannerClientTOMLUsesSelectedMinimumMTU(t *testing.T) {
	connection := model.ConnectionProfile{
		Domain:           "scan.example.com",
		EncryptionKey:    "abc",
		EncryptionMethod: 1,
	}
	settings := model.DefaultSettingsProfile()
	settings.MinUploadMTU = 44
	settings.MinDownloadMTU = 128

	toml := storm.RenderConnectionUpgradeScannerClientTOML(connection, settings, 23001, 23002, 200)
	for _, line := range []string{
		`MIN_UPLOAD_MTU = 44`,
		`MAX_UPLOAD_MTU = 44`,
		`MIN_DOWNLOAD_MTU = 128`,
		`MAX_DOWNLOAD_MTU = 128`,
	} {
		if !strings.Contains(toml, line) {
			t.Fatalf("connection-upgrade scanner TOML missing %q:\n%s", line, toml)
		}
	}
}

func TestDNSScannerCommandArgsUseNormalClientMode(t *testing.T) {
	args := dnsScannerCommandArgs("client.toml", "bootstrap.resolvers")
	if containsString(args, "-scan-only") {
		t.Fatalf("DNS scanner should launch the normal client mode, got args %#v", args)
	}
	if !reflect.DeepEqual(args, []string{"-config", "client.toml", "-resolvers", "bootstrap.resolvers"}) {
		t.Fatalf("unexpected scanner command args: %#v", args)
	}
}

func TestScannerBootstrapResolverFileUsesConnectionResolverProfile(t *testing.T) {
	state := model.DefaultAppState()
	state.ResolverProfiles = append(state.ResolverProfiles, model.ResolverProfile{
		ID:           "resolver-bootstrap",
		Name:         "Bootstrap",
		ResolverText: "9.9.9.9\n149.112.112.112",
	})
	state.ConnectionProfiles[0].ResolverProfileID = "resolver-bootstrap"
	app := &App{state: state}

	path, err := app.scannerBootstrapResolverFile(state.ConnectionProfiles[0].ID, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(raw)), "9.9.9.9\n149.112.112.112"; got != want {
		t.Fatalf("unexpected bootstrap resolvers:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestConnectionUpgradeScanPlanUsesUploadDuplicationBootstrap(t *testing.T) {
	state := model.DefaultAppState()
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8\n9.9.9.9\n4.4.4.4"
	settings := model.DefaultSettingsProfile()
	settings.UploadDuplication = 2
	settings.MTUTestParallelismResolvers = 37
	app := &App{state: state, scannerState: model.ScannerState{Status: model.ScannerIdle}}

	plan, err := app.connectionUpgradeScanPlan(state, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.BootstrapResolvers, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("unexpected bootstrap resolvers: %#v", plan.BootstrapResolvers)
	}
	if len(plan.CandidateResolvers) != 4 || plan.CandidateTotal != 4 {
		t.Fatalf("unexpected candidate resolver plan: %#v", plan)
	}
	if plan.ScanParallel != 37 {
		t.Fatalf("expected settings MTU parallelism, got %d", plan.ScanParallel)
	}
}

func TestBuildLaunchConfigKeepsFullResolverProfileForFastStartup(t *testing.T) {
	state := model.DefaultAppState()
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8"
	state.ConnectionProfiles[0].Domain = "scan.example.com"
	state.ConnectionProfiles[0].EncryptionKey = "secret"

	cfg, err := storm.BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Resolvers != "1.1.1.1\n8.8.8.8" {
		t.Fatalf("expected full resolver profile, got %q", cfg.Resolvers)
	}
	if cfg.FullInitialMTUScan {
		t.Fatal("expected default startup to use MasterDNS early-start mode")
	}

	fullScanSettings := model.DefaultSettingsProfile()
	fullScanSettings.ID = "settings-full-scan"
	fullScanSettings.Name = "Full scan"
	fullScanSettings.ConnectionStartupMode = model.ConnectionStartupModeFullScan
	state.SettingsProfiles = append(state.SettingsProfiles, fullScanSettings)
	state.SelectedSettingsProfileID = fullScanSettings.ID
	cfg, err = storm.BuildLaunchConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.FullInitialMTUScan {
		t.Fatal("expected full-scan setting to request blocking MasterDNS MTU scan")
	}
}

func TestConnectionUpgradeScanPlanPrefersScannerInputFile(t *testing.T) {
	state := model.DefaultAppState()
	state.ResolverProfiles[0].ResolverText = "1.1.1.1\n8.8.8.8\n9.9.9.9"
	settings := model.DefaultSettingsProfile()
	settings.UploadDuplication = 2
	inputPath := filepath.Join(t.TempDir(), "scanner-input.resolvers")
	if err := os.WriteFile(inputPath, []byte("4.4.4.4\n208.67.222.222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := &App{
		state:            state,
		scannerInputPath: inputPath,
		scannerState: model.ScannerState{
			Status:        model.ScannerCompleted,
			InputFileName: "scanner-input.resolvers",
			ScanParallel:  222,
			Total:         5,
			Invalid:       1,
			Duplicates:    2,
		},
	}

	plan, err := app.connectionUpgradeScanPlan(state, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.BootstrapResolvers, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("unexpected bootstrap resolvers: %#v", plan.BootstrapResolvers)
	}
	if plan.CandidateInputPath != inputPath || len(plan.CandidateResolvers) != 0 {
		t.Fatalf("expected scanner input source, got %#v", plan)
	}
	if plan.CandidateTotal != 5 || plan.CandidateInvalid != 1 || plan.CandidateDuplicates != 2 {
		t.Fatalf("unexpected scanner input counts: %#v", plan)
	}
	if plan.ScanParallel != 222 {
		t.Fatalf("expected scanner parallel override, got %d", plan.ScanParallel)
	}
}

func TestScannerCompletesFromNormalResolverStateAndFullReport(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "valid.resolvers")
	snapshotPath := filepath.Join(dir, "last-scan.json")
	report := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "4.4.4.4:53", "208.67.222.222:53"}
	if err := os.WriteFile(resultsPath, []byte(strings.Join(report, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{
		scannerRunID:        17,
		scannerCancel:       cancel,
		scannerSnapshotPath: snapshotPath,
		scannerResultsPath:  resultsPath,
		scannerState: model.ScannerState{
			Status:       model.ScannerRunning,
			Total:        5,
			ScanParallel: 200,
			StartedAt:    1000,
		},
	}

	app.applyDNSScannerEvent(17, storm.ScannerEvent{Event: "started", Total: 5})
	app.applyDNSScannerResolverState(17, model.ResolverRuntimeState{
		TotalCount:    5,
		ValidCount:    5,
		RejectedCount: 0,
		PendingCount:  0,
		ValidResolvers: []string{
			"sample-only:53",
		},
	})

	if app.scannerState.Status != model.ScannerCompleted {
		t.Fatalf("expected scanner completed, got %#v", app.scannerState)
	}
	if app.scannerState.Completed != 5 || app.scannerState.Valid != 5 || app.scannerState.Rejected != 0 {
		t.Fatalf("unexpected scanner counts: %#v", app.scannerState)
	}
	if !reflect.DeepEqual(app.scannerState.ValidResolvers, report) {
		t.Fatalf("expected full report-backed valid resolver list, got %#v", app.scannerState.ValidResolvers)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected scanner process context to be cancelled after completion")
	}
}

func TestConnectionUpgradeScannerCompletionExposesRestartPrompt(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "valid.resolvers")
	if err := os.WriteFile(resultsPath, []byte("1.1.1.1\n8.8.8.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{
		scannerRunID:        31,
		scannerCancel:       cancel,
		scannerResultsPath:  resultsPath,
		scannerInputStarted: true,
		scannerState: model.ScannerState{
			Status:                      model.ScannerRunning,
			Mode:                        dnsScannerModeUpgrade,
			SelectedConnectionProfileID: model.DefaultConnectionProfileID,
			BootstrapResolverCount:      2,
			Total:                       4,
		},
	}

	app.applyDNSScannerResolverState(31, model.ResolverRuntimeState{
		TotalCount:    4,
		ValidCount:    2,
		RejectedCount: 2,
		PendingCount:  0,
	})

	if app.scannerState.Status != model.ScannerCompleted {
		t.Fatalf("expected completed scanner state, got %#v", app.scannerState)
	}
	if !app.scannerState.RestartAvailable {
		t.Fatalf("expected restart prompt, got %#v", app.scannerState)
	}
	if app.scannerState.ScannedResolverCount != 4 || app.scannerState.Valid != 2 {
		t.Fatalf("unexpected scanner counts: %#v", app.scannerState)
	}
	if !strings.Contains(app.scannerState.Message, "restart the VPN") {
		t.Fatalf("unexpected completion message: %q", app.scannerState.Message)
	}
	if ctx.Err() == nil {
		t.Fatal("expected scanner process context to be cancelled after completion")
	}
}

func TestDismissScannerConnectionUpgradeHidesRestartPrompt(t *testing.T) {
	app := &App{scannerState: model.ScannerState{
		Status:           model.ScannerCompleted,
		Mode:             dnsScannerModeUpgrade,
		RestartAvailable: true,
		ValidResolvers:   []string{"1.1.1.1"},
	}}

	state, err := app.DismissScannerConnectionUpgrade()
	if err != nil {
		t.Fatal(err)
	}
	if state.RestartAvailable || app.scannerState.RestartAvailable {
		t.Fatalf("expected restart prompt to be hidden, got %#v", state)
	}
	if state.Message != "Keeping the current VPN session." {
		t.Fatalf("unexpected dismiss message: %q", state.Message)
	}
}

func TestScannerIgnoresBootstrapResolverStateBeforeInputScanStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{
		scannerRunID:  21,
		scannerCancel: cancel,
		scannerState: model.ScannerState{
			Status:       model.ScannerRunning,
			Total:        15000,
			ScanParallel: 200,
			StartedAt:    1000,
		},
	}

	app.applyDNSScannerResolverState(21, model.ResolverRuntimeState{
		TotalCount:    1,
		ValidCount:    1,
		RejectedCount: 0,
		PendingCount:  0,
	})

	if app.scannerState.Status != model.ScannerRunning {
		t.Fatalf("bootstrap resolver state should not complete scanner, got %#v", app.scannerState)
	}
	if app.scannerState.Total != 15000 || app.scannerState.Completed != 0 || app.scannerState.Valid != 0 || app.scannerState.Rejected != 0 {
		t.Fatalf("bootstrap resolver state should not overwrite input counts, got %#v", app.scannerState)
	}
	select {
	case <-ctx.Done():
		t.Fatal("bootstrap resolver state should not cancel scanner process")
	default:
	}
}

func TestScannerStartedEventEnablesInputResolverCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{
		scannerRunID:  22,
		scannerCancel: cancel,
		scannerState: model.ScannerState{
			Status:       model.ScannerRunning,
			Total:        15000,
			ScanParallel: 200,
			StartedAt:    1000,
		},
	}

	app.applyDNSScannerEvent(22, storm.ScannerEvent{Event: "started", Total: 15000})
	app.applyDNSScannerResolverState(22, model.ResolverRuntimeState{
		TotalCount:    15000,
		ValidCount:    150,
		RejectedCount: 14850,
		PendingCount:  0,
	})

	if app.scannerState.Status != model.ScannerCompleted {
		t.Fatalf("expected scanner completed after input scan resolver state, got %#v", app.scannerState)
	}
	if app.scannerState.Total != 15000 || app.scannerState.Completed != 15000 || app.scannerState.Valid != 150 || app.scannerState.Rejected != 14850 {
		t.Fatalf("unexpected scanner counts after input completion: %#v", app.scannerState)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected scanner process context to be cancelled after input completion")
	}
}

func TestScannerIgnoresNonInputProgressAfterInputScanStarts(t *testing.T) {
	app := &App{
		scannerRunID:        23,
		scannerInputStarted: true,
		scannerState: model.ScannerState{
			Status:       model.ScannerRunning,
			Total:        15000,
			Completed:    14999,
			Valid:        150,
			Rejected:     14849,
			ScanParallel: 200,
			StartedAt:    1000,
		},
	}

	app.handleDNSScannerLogLine(23, "WD_PROGRESS phase=runtime percent=98")
	app.handleDNSScannerLogLine(23, "WD_PROGRESS phase=mtu percent=10 completed=0 total=1 valid=0 rejected=0")

	if app.scannerState.Completed != 14999 || app.scannerState.Total != 15000 || app.scannerState.Valid != 150 || app.scannerState.Rejected != 14849 {
		t.Fatalf("non-input progress should not reset scanner counts, got %#v", app.scannerState)
	}
}

func TestScannerIgnoresZeroTotalResolverStateAfterInputScanStarts(t *testing.T) {
	app := &App{
		scannerRunID:        24,
		scannerInputStarted: true,
		scannerState: model.ScannerState{
			Status:       model.ScannerRunning,
			Total:        15000,
			Completed:    14999,
			Valid:        150,
			Rejected:     14849,
			ScanParallel: 200,
			StartedAt:    1000,
		},
	}

	app.applyDNSScannerResolverState(24, model.ResolverRuntimeState{
		TotalCount:    0,
		ValidCount:    0,
		RejectedCount: 0,
		PendingCount:  0,
	})

	if app.scannerState.Completed != 14999 || app.scannerState.Total != 15000 || app.scannerState.Valid != 150 || app.scannerState.Rejected != 14849 {
		t.Fatalf("zero-total resolver state should not reset scanner counts, got %#v", app.scannerState)
	}
}

func TestFinishDNSScannerRunPreservesCompletedCounts(t *testing.T) {
	app := &App{
		scannerRunID: 25,
		scannerState: model.ScannerState{
			Status:         model.ScannerRunning,
			Total:          10,
			Completed:      0,
			Valid:          2,
			Rejected:       0,
			ValidResolvers: []string{"1.1.1.1:53", "8.8.8.8:53"},
			ScanParallel:   200,
			StartedAt:      1000,
		},
	}

	app.finishDNSScannerRun(25, model.ScannerCompleted, "DNS scanner completed")

	if app.scannerState.Status != model.ScannerCompleted {
		t.Fatalf("expected completed scanner state, got %#v", app.scannerState)
	}
	if app.scannerState.Completed != 10 || app.scannerState.Total != 10 || app.scannerState.Valid != 2 || app.scannerState.Rejected != 8 {
		t.Fatalf("finish should preserve and finalize completed scanner counts, got %#v", app.scannerState)
	}
}

func TestFinishDNSScannerRunPreservesAutoCompletedState(t *testing.T) {
	app := &App{
		scannerRunID: 3,
		scannerState: model.ScannerState{
			Status:  model.ScannerCompleted,
			Message: "DNS scanner completed: 2 valid, 1 rejected",
			Total:   3,
			Valid:   2,
		},
	}

	app.finishDNSScannerRun(3, model.ScannerCancelled, "DNS scanner cancelled")

	if app.scannerState.Status != model.ScannerCompleted {
		t.Fatalf("expected completed state to survive process cancellation, got %#v", app.scannerState)
	}
	if app.scannerState.Message != "DNS scanner completed: 2 valid, 1 rejected" {
		t.Fatalf("unexpected completion message: %q", app.scannerState.Message)
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

func TestCreateResolverProfileFromValidatorResultsCreatesResolverProfile(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	app := &App{store: store, state: state}

	result, err := app.CreateResolverProfileFromValidatorResults(model.ValidatorResolverProfileRequest{
		Results: []model.ValidatorResolverProfileInput{
			{Endpoint: "1.1.1.1:53", Host: "1.1.1.1.", Port: 53},
			{Endpoint: "8.8.8.8:5353", Host: "8.8.8.8", Port: 5353},
			{Endpoint: "1.1.1.1:53", Host: "1.1.1.1", Port: 53},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 || result.Skipped != 1 {
		t.Fatalf("expected 2 imported and 1 skipped, got imported=%d skipped=%d", result.Imported, result.Skipped)
	}
	if len(result.State.ConnectionProfiles) != 1 {
		t.Fatalf("validator import should not create connection profiles, got %#v", result.State.ConnectionProfiles)
	}
	if len(result.State.ResolverProfiles) != 2 {
		t.Fatalf("expected default and validated resolver profiles, got %#v", result.State.ResolverProfiles)
	}
	imported := result.State.ResolverProfiles[1]
	if imported.ID == "" || imported.Name != "Validated Resolvers" {
		t.Fatalf("unexpected imported resolver identity: %#v", imported)
	}
	if imported.ResolverText != "1.1.1.1\n8.8.8.8:5353" {
		t.Fatalf("unexpected resolver text: %q", imported.ResolverText)
	}
	if result.Profile.ID != imported.ID {
		t.Fatalf("expected result profile to match imported resolver, got %#v", result.Profile)
	}
	if result.State.SelectedResolverProfileID != imported.ID || result.State.ConnectionProfiles[0].ResolverProfileID != imported.ID {
		t.Fatalf("expected validated resolver selected on active connection, selected=%q connection=%q", result.State.SelectedResolverProfileID, result.State.ConnectionProfiles[0].ResolverProfileID)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ResolverProfiles) != 2 {
		t.Fatalf("expected validated resolver profile to persist, got %#v", loaded.ResolverProfiles)
	}
}

func TestCreateResolverProfileFromValidatorResultsRejectsNoValidResults(t *testing.T) {
	app := &App{
		store: profiles.NewStore(filepath.Join(t.TempDir(), "state.json")),
		state: model.DefaultAppState(),
	}

	_, err := app.CreateResolverProfileFromValidatorResults(model.ValidatorResolverProfileRequest{
		Results: []model.ValidatorResolverProfileInput{{Endpoint: "scan.example.com:53", Host: "scan.example.com", Port: 53}},
	})
	if err == nil || !strings.Contains(err.Error(), "no valid validator results selected") {
		t.Fatalf("expected no valid results error, got %v", err)
	}
}

func TestCreateResolverProfileFromValidatorResultsDoesNotSelectWhileConnecting(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	state.Runtime.Status = model.RuntimeConnecting
	state.Runtime.ActiveConnectionID = model.DefaultConnectionProfileID
	app := &App{store: store, state: state}

	result, err := app.CreateResolverProfileFromValidatorResults(model.ValidatorResolverProfileRequest{
		Results: []model.ValidatorResolverProfileInput{
			{Endpoint: "9.9.9.9:53", Host: "9.9.9.9", Port: 53},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State.SelectedResolverProfileID != model.DefaultResolverProfileID {
		t.Fatalf("validator import changed locked resolver selection: %q", result.State.SelectedResolverProfileID)
	}
	if result.State.ConnectionProfiles[0].ResolverProfileID != "" {
		t.Fatalf("validator import changed active connection resolver: %q", result.State.ConnectionProfiles[0].ResolverProfileID)
	}
}

func TestSaveScannerResolverProfileCreatesFileBackedProfile(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	app := &App{
		store: store,
		state: model.DefaultAppState(),
		scannerState: model.ScannerState{
			Status:         model.ScannerCompleted,
			ValidResolvers: []string{"1.1.1.1:53", "8.8.8.8"},
		},
	}

	result, err := app.SaveScannerResolverProfile("DNS Scan")
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 || result.Profile.Name != "DNS Scan" || result.Profile.ResolverSource != "file" {
		t.Fatalf("unexpected saved scanner profile: %#v", result)
	}
	if result.State.SelectedResolverProfileID != result.Profile.ID || result.State.ConnectionProfiles[0].ResolverProfileID != result.Profile.ID {
		t.Fatalf("expected saved scanner profile to be selected, got state=%#v", result.State)
	}
}

func TestSaveScannerResolverProfileDoesNotSelectWhileConnected(t *testing.T) {
	store := profiles.NewStore(filepath.Join(t.TempDir(), "state.json"))
	state := model.DefaultAppState()
	state.Runtime.Status = model.RuntimeConnected
	state.Runtime.ActiveConnectionID = model.DefaultConnectionProfileID
	app := &App{
		store: store,
		state: state,
		scannerState: model.ScannerState{
			Status:         model.ScannerCompleted,
			ValidResolvers: []string{"9.9.9.9:53"},
		},
	}

	result, err := app.SaveScannerResolverProfile("Connected DNS Scan")
	if err != nil {
		t.Fatal(err)
	}
	if result.State.SelectedResolverProfileID != model.DefaultResolverProfileID || result.State.ConnectionProfiles[0].ResolverProfileID != "" {
		t.Fatalf("scanner save changed locked resolver selection: selected=%q connection=%q", result.State.SelectedResolverProfileID, result.State.ConnectionProfiles[0].ResolverProfileID)
	}
}

func TestScannerValidResolversPersistAcrossInterruptedRun(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "last-scan.json")
	resultsPath := filepath.Join(dir, "last-valid.resolvers")
	inputPath := filepath.Join(dir, "input.resolvers")
	app := &App{
		scannerRunID:        12,
		scannerSnapshotPath: snapshotPath,
		scannerResultsPath:  resultsPath,
		scannerInputPath:    inputPath,
		scannerState: model.ScannerState{
			Status:       model.ScannerRunning,
			Total:        10,
			ScanParallel: 25,
			StartedAt:    1000,
		},
	}

	app.applyDNSScannerEvent(12, storm.ScannerEvent{Event: "valid", Resolver: "1.1.1.1:53"})
	app.applyDNSScannerEvent(12, storm.ScannerEvent{Event: "valid", Resolver: "1.1.1.1:53"})
	app.applyDNSScannerEvent(12, storm.ScannerEvent{Event: "valid", Resolver: "8.8.8.8"})

	raw, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(raw)), "1.1.1.1:53\n8.8.8.8"; got != want {
		t.Fatalf("unexpected persisted scanner results:\ngot:\n%s\nwant:\n%s", got, want)
	}

	recovered, recoveredInputPath, ok := loadPersistedScannerSnapshot(snapshotPath, resultsPath)
	if !ok {
		t.Fatal("expected interrupted scanner results to recover")
	}
	if recoveredInputPath != inputPath {
		t.Fatalf("expected recovered input path %q, got %q", inputPath, recoveredInputPath)
	}
	if recovered.Status != model.ScannerFailed || recovered.Phase != "recovered" {
		t.Fatalf("expected interrupted run to recover as failed/recovered, got %#v", recovered)
	}
	if recovered.Valid != 2 || !reflect.DeepEqual(recovered.ValidResolvers, []string{"1.1.1.1:53", "8.8.8.8"}) {
		t.Fatalf("unexpected recovered valid resolvers: %#v", recovered)
	}
}

func TestCancelScannerScanRefreshesPartialReport(t *testing.T) {
	dir := t.TempDir()
	resultsPath := filepath.Join(dir, "last-valid.resolvers")
	if err := os.WriteFile(resultsPath, []byte("1.1.1.1:53\n8.8.8.8:53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	app := &App{
		scannerCancel:      cancel,
		scannerResultsPath: resultsPath,
		scannerState: model.ScannerState{
			Status: model.ScannerRunning,
			Total:  10,
		},
	}

	state, err := app.CancelScannerScan()
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != model.ScannerCancelled || state.Valid != 2 {
		t.Fatalf("expected cancelled state with partial valid resolvers, got %#v", state)
	}
	if !reflect.DeepEqual(state.ValidResolvers, []string{"1.1.1.1:53", "8.8.8.8:53"}) {
		t.Fatalf("unexpected partial valid resolvers: %#v", state.ValidResolvers)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected cancel function to be called")
	}
}

func TestClearScannerResultsRemovesPersistedScannerFiles(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "last-scan.json")
	resultsPath := filepath.Join(dir, "last-valid.resolvers")
	inputPath := filepath.Join(dir, "input.resolvers")
	for path, content := range map[string]string{
		snapshotPath: "{}",
		resultsPath:  "1.1.1.1\n",
		inputPath:    "1.1.1.1\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{
		scannerSnapshotPath: snapshotPath,
		scannerResultsPath:  resultsPath,
		scannerInputPath:    inputPath,
		scannerState: model.ScannerState{
			Status:         model.ScannerCompleted,
			ValidResolvers: []string{"1.1.1.1"},
		},
	}

	if _, err := app.ClearScannerResults(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{snapshotPath, resultsPath, inputPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, stat err=%v", path, err)
		}
	}
}
