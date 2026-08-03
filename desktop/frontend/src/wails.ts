import type {
  AppState,
  CloudflarePingResult,
  ConnectionImportResult,
  ConnectionProfile,
  ConnectionTestResolver,
  ConnectionTestResult,
  FirewallStatus,
  ParallelTestPresetOption,
  ParallelTestState,
  ProxyCountryLookupResult,
  ResolverImportResult,
  ResolverPreviewPage,
  ResolverProfile,
  ResolverTextValidation,
  RuntimeType,
  ScannerStartRequest,
  ScannerState,
  SettingsProfile,
  V2RayDuplicateRemovalResult,
  V2RayWhiteIPGenerateResult,
  V2RayImportResult,
  V2RayPingResult,
  V2RayProfile,
  V2RaySettingsProfile,
  V2RaySubscription,
  V2RaySubscriptionRefreshResult,
  V2RayWhiteIPImportResult,
  ValidatorRangeOption,
  ValidatorRangeImportResult,
  ValidatorRangeRequest,
  ValidatorResolverProfileRequest,
  ValidatorRequest,
  ValidatorResultFile,
  ValidatorState,
} from "./types";

type WailsNotificationOptions = {
  id: string;
  title: string;
  subtitle?: string;
  body?: string;
  data?: Record<string, unknown>;
};

type AppApi = {
  GetAppState(): Promise<AppState>;
  CheckFirewallStatus(): Promise<FirewallStatus>;
  GetSystemLANIP(): Promise<string>;
  SaveConnectionProfile(profile: ConnectionProfile): Promise<AppState>;
  ImportConnectionProfiles(rawText: string, importType: string): Promise<ConnectionImportResult>;
  DeleteConnectionProfile(id: string): Promise<AppState>;
  DeleteConnectionProfiles(ids: string[]): Promise<AppState>;
  TestConnectionProfile(profile: ConnectionProfile, trustedResolvers: ConnectionTestResolver[]): Promise<ConnectionTestResult>;
  SelectConnectionProfile(id: string): Promise<AppState>;
  ReorderConnectionProfiles(ids: string[]): Promise<AppState>;
  SaveV2RayProfile(profile: V2RayProfile): Promise<AppState>;
  ImportV2RayProfiles(rawText: string): Promise<V2RayImportResult>;
  GetDefaultWhiteIPList(): Promise<string>;
  GenerateV2RayWhiteIPProfiles(configText: string, whiteIPText: string): Promise<V2RayWhiteIPGenerateResult>;
  ImportV2RayWhiteIPProfiles(configText: string, whiteIPText: string): Promise<V2RayWhiteIPImportResult>;
  SaveV2RaySubscription(subscription: V2RaySubscription): Promise<AppState>;
  RefreshV2RaySubscription(id: string): Promise<V2RaySubscriptionRefreshResult>;
  DeleteV2RaySubscription(id: string): Promise<AppState>;
  ExportV2RayProfileLink(profile: V2RayProfile): Promise<string>;
  ExportAllV2RayProfileLinks(): Promise<string>;
  DeleteV2RayProfile(id: string): Promise<AppState>;
  DeleteV2RayProfiles(ids: string[]): Promise<AppState>;
  SelectV2RayProfile(id: string): Promise<AppState>;
  ReorderV2RayProfiles(ids: string[]): Promise<AppState>;
  PingV2RayProfiles(): Promise<V2RayPingResult[]>;
  PingV2RayProfileIDs(ids: string[]): Promise<V2RayPingResult[]>;
  PingV2RayProfile(profile: V2RayProfile): Promise<V2RayPingResult>;
  SpeedTestV2RayProfileIDs(ids: string[]): Promise<V2RayPingResult[]>;
  RealDelayV2RayProfileIDs(ids: string[]): Promise<V2RayPingResult[]>;
  CancelV2RayProfileTests(): Promise<void>;
  DeleteDuplicateV2RayProfiles(): Promise<V2RayDuplicateRemovalResult>;
  SaveV2RaySettingsProfile(profile: V2RaySettingsProfile): Promise<AppState>;
  DeleteV2RaySettingsProfile(id: string): Promise<AppState>;
  SelectV2RaySettingsProfile(id: string): Promise<AppState>;
  ReorderV2RaySettingsProfiles(ids: string[]): Promise<AppState>;
  GetDefaultV2RaySettingsProfile(): Promise<V2RaySettingsProfile>;
  SaveResolverProfile(profile: ResolverProfile): Promise<AppState>;
  SaveResolverProfileSnapshot(profile: ResolverProfile): Promise<AppState>;
  ImportResolverProfileFile(): Promise<ResolverImportResult>;
  DeleteResolverProfile(id: string): Promise<AppState>;
  SelectResolverProfile(id: string): Promise<AppState>;
  ReorderResolverProfiles(ids: string[]): Promise<AppState>;
  GetResolverProfilePreview(id: string, offset: number, limit: number): Promise<ResolverPreviewPage>;
  SaveSettingsProfile(profile: SettingsProfile): Promise<AppState>;
  ImportSettingsProfileToml(rawText: string, suggestedName: string, importType: string): Promise<AppState>;
  DeleteSettingsProfile(id: string): Promise<AppState>;
  SelectSettingsProfile(id: string): Promise<AppState>;
  ReorderSettingsProfiles(ids: string[]): Promise<AppState>;
  GetDefaultSettingsProfile(): Promise<SettingsProfile>;
  ValidateResolverText(rawText: string): Promise<ResolverTextValidation>;
  StartConnection(): Promise<AppState>;
  StartWhiteDNSVPNConnection(): Promise<AppState>;
  RefreshWhiteDNSVPNConnection(): Promise<AppState>;
  SaveWhiteDNSVPNFrontingIPs(rawText: string): Promise<AppState>;
  StartV2RayConnection(): Promise<AppState>;
  StopConnection(): Promise<AppState>;
  ClearRuntimeLogs(): Promise<AppState>;
  ClearRuntimeLogsForType(runtimeType: RuntimeType): Promise<AppState>;
  SaveRuntimeLogs(rawText: string): Promise<string>;
  PingCloudflare(): Promise<CloudflarePingResult>;
  LookupProxyCountry(): Promise<ProxyCountryLookupResult>;
  SetResolverMTUScanPaused(paused: boolean): Promise<AppState>;
  GetParallelTestState(): Promise<ParallelTestState>;
  GetParallelTestPresetOptions(): Promise<ParallelTestPresetOption[]>;
  SaveParallelTestPresets(presetIds: string[]): Promise<AppState>;
  StartParallelTest(presetIds: string[]): Promise<ParallelTestState>;
  CancelParallelTest(): Promise<ParallelTestState>;
  GetValidatorState(): Promise<ValidatorState>;
  GetDefaultValidatorRanges(): Promise<ValidatorRangeOption[]>;
  ParseValidatorRangeInput(rawText: string): Promise<ValidatorRangeImportResult>;
  StartValidatorScan(request: ValidatorRequest): Promise<ValidatorState>;
  StartValidatorRangeScan(request: ValidatorRangeRequest): Promise<ValidatorState>;
  SetValidatorPaused(paused: boolean): Promise<ValidatorState>;
  CancelValidatorScan(): Promise<ValidatorState>;
  ClearValidatorResults(): Promise<ValidatorState>;
  CreateResolverProfileFromValidatorResults(request: ValidatorResolverProfileRequest): Promise<ResolverImportResult>;
  ListValidatorResultFiles(): Promise<ValidatorResultFile[]>;
  OpenValidatorResultFile(name: string): Promise<void>;
  DeleteValidatorResultFile(name: string): Promise<ValidatorResultFile[]>;
  GetScannerState(): Promise<ScannerState>;
  SelectScannerInputFile(): Promise<ScannerState>;
  StartScannerScan(request: ScannerStartRequest): Promise<ScannerState>;
  SetScannerPaused(paused: boolean): Promise<ScannerState>;
  CancelScannerScan(): Promise<ScannerState>;
  ClearScannerResults(): Promise<ScannerState>;
  SaveScannerResolverProfile(name: string): Promise<ResolverImportResult>;
  ApplyScannerConnectionUpgrade(action: string): Promise<AppState>;
  DismissScannerConnectionUpgrade(): Promise<ScannerState>;
  ExportClientToml(): Promise<string>;
  ExportConnectionProfileLink(profile: ConnectionProfile): Promise<string>;
  ExportAllConnectionProfileLinks(): Promise<string>;
  ExportSettingsProfileToml(profile: SettingsProfile): Promise<string>;
  ExportBackup(): Promise<string>;
  ImportBackup(rawText: string): Promise<AppState>;
  Quit(): Promise<void>;
};

declare global {
  interface Window {
    go?: {
      main?: {
        App?: AppApi;
      };
    };
    runtime?: {
      EventsOn(eventName: string, callback: (...data: unknown[]) => void): (() => void) | void;
      BrowserOpenURL?(url: string): void;
      InitializeNotifications?(): Promise<void>;
      CleanupNotifications?(): Promise<void>;
      IsNotificationAvailable?(): Promise<boolean>;
      RequestNotificationAuthorization?(): Promise<boolean>;
      CheckNotificationAuthorization?(): Promise<boolean>;
      SendNotification?(options: WailsNotificationOptions): Promise<void>;
    };
  }
}

function app(): AppApi {
  const api = window.go?.main?.App;
  if (!api) {
    throw new Error("WhiteDNS backend is not available. Run this UI inside Wails.");
  }
  return api;
}

export const backend = {
  getAppState: () => app().GetAppState(),
  checkFirewallStatus: () => app().CheckFirewallStatus(),
  getSystemLANIP: () => app().GetSystemLANIP(),
  saveConnectionProfile: (profile: ConnectionProfile) => app().SaveConnectionProfile(profile),
  importConnectionProfiles: (rawText: string, importType: string) => app().ImportConnectionProfiles(rawText, importType),
  deleteConnectionProfile: (id: string) => app().DeleteConnectionProfile(id),
  deleteConnectionProfiles: (ids: string[]) => app().DeleteConnectionProfiles(ids),
  testConnectionProfile: (profile: ConnectionProfile, trustedResolvers: ConnectionTestResolver[]) => app().TestConnectionProfile(profile, trustedResolvers),
  selectConnectionProfile: (id: string) => app().SelectConnectionProfile(id),
  reorderConnectionProfiles: (ids: string[]) => app().ReorderConnectionProfiles(ids),
  saveV2RayProfile: (profile: V2RayProfile) => app().SaveV2RayProfile(profile),
  importV2RayProfiles: (rawText: string) => app().ImportV2RayProfiles(rawText),
  getDefaultWhiteIPList: () => app().GetDefaultWhiteIPList(),
  generateV2RayWhiteIpProfiles: (configText: string, whiteIPText: string) => app().GenerateV2RayWhiteIPProfiles(configText, whiteIPText),
  importV2RayWhiteIpProfiles: (configText: string, whiteIPText: string) => app().ImportV2RayWhiteIPProfiles(configText, whiteIPText),
  saveV2RaySubscription: (subscription: V2RaySubscription) => app().SaveV2RaySubscription(subscription),
  refreshV2RaySubscription: (id: string) => app().RefreshV2RaySubscription(id),
  deleteV2RaySubscription: (id: string) => app().DeleteV2RaySubscription(id),
  exportV2RayProfileLink: (profile: V2RayProfile) => app().ExportV2RayProfileLink(profile),
  exportAllV2RayProfileLinks: () => app().ExportAllV2RayProfileLinks(),
  deleteV2RayProfile: (id: string) => app().DeleteV2RayProfile(id),
  deleteV2RayProfiles: (ids: string[]) => app().DeleteV2RayProfiles(ids),
  selectV2RayProfile: (id: string) => app().SelectV2RayProfile(id),
  reorderV2RayProfiles: (ids: string[]) => app().ReorderV2RayProfiles(ids),
  pingV2RayProfiles: () => app().PingV2RayProfiles(),
  pingV2RayProfileIds: (ids: string[]) => app().PingV2RayProfileIDs(ids),
  pingV2RayProfile: (profile: V2RayProfile) => app().PingV2RayProfile(profile),
  speedTestV2RayProfileIds: (ids: string[]) => app().SpeedTestV2RayProfileIDs(ids),
  realDelayV2RayProfileIds: (ids: string[]) => app().RealDelayV2RayProfileIDs(ids),
  cancelV2RayProfileTests: () => app().CancelV2RayProfileTests(),
  deleteDuplicateV2RayProfiles: () => app().DeleteDuplicateV2RayProfiles(),
  saveV2RaySettingsProfile: (profile: V2RaySettingsProfile) => app().SaveV2RaySettingsProfile(profile),
  deleteV2RaySettingsProfile: (id: string) => app().DeleteV2RaySettingsProfile(id),
  selectV2RaySettingsProfile: (id: string) => app().SelectV2RaySettingsProfile(id),
  reorderV2RaySettingsProfiles: (ids: string[]) => app().ReorderV2RaySettingsProfiles(ids),
  getDefaultV2RaySettingsProfile: () => app().GetDefaultV2RaySettingsProfile(),
  saveResolverProfile: (profile: ResolverProfile) => app().SaveResolverProfile(profile),
  saveResolverProfileSnapshot: (profile: ResolverProfile) => app().SaveResolverProfileSnapshot(profile),
  importResolverProfileFile: () => app().ImportResolverProfileFile(),
  deleteResolverProfile: (id: string) => app().DeleteResolverProfile(id),
  selectResolverProfile: (id: string) => app().SelectResolverProfile(id),
  reorderResolverProfiles: (ids: string[]) => app().ReorderResolverProfiles(ids),
  getResolverProfilePreview: (id: string, offset: number, limit: number) => app().GetResolverProfilePreview(id, offset, limit),
  saveSettingsProfile: (profile: SettingsProfile) => app().SaveSettingsProfile(profile),
  importSettingsProfileToml: (rawText: string, suggestedName: string, importType: string) => app().ImportSettingsProfileToml(rawText, suggestedName, importType),
  deleteSettingsProfile: (id: string) => app().DeleteSettingsProfile(id),
  selectSettingsProfile: (id: string) => app().SelectSettingsProfile(id),
  reorderSettingsProfiles: (ids: string[]) => app().ReorderSettingsProfiles(ids),
  getDefaultSettingsProfile: () => app().GetDefaultSettingsProfile(),
  validateResolverText: (rawText: string) => app().ValidateResolverText(rawText),
  startConnection: () => app().StartConnection(),
  startWhiteDNSVPNConnection: () => app().StartWhiteDNSVPNConnection(),
  refreshWhiteDNSVPNConnection: () => app().RefreshWhiteDNSVPNConnection(),
  saveWhiteDNSVPNFrontingIps: (rawText: string) => app().SaveWhiteDNSVPNFrontingIPs(rawText),
  startV2RayConnection: () => app().StartV2RayConnection(),
  stopConnection: () => app().StopConnection(),
  clearRuntimeLogs: (runtimeType: RuntimeType = "") => app().ClearRuntimeLogsForType(runtimeType),
  saveRuntimeLogs: (rawText: string) => app().SaveRuntimeLogs(rawText),
  pingCloudflare: () => app().PingCloudflare(),
  lookupProxyCountry: () => app().LookupProxyCountry(),
  setResolverMTUScanPaused: (paused: boolean) => app().SetResolverMTUScanPaused(paused),
  getParallelTestState: () => app().GetParallelTestState(),
  getParallelTestPresetOptions: () => app().GetParallelTestPresetOptions(),
  saveParallelTestPresets: (presetIds: string[]) => app().SaveParallelTestPresets(presetIds),
  startParallelTest: (presetIds: string[]) => app().StartParallelTest(presetIds),
  cancelParallelTest: () => app().CancelParallelTest(),
  getValidatorState: () => app().GetValidatorState(),
  getDefaultValidatorRanges: () => app().GetDefaultValidatorRanges(),
  parseValidatorRangeInput: (rawText: string) => app().ParseValidatorRangeInput(rawText),
  startValidatorScan: (request: ValidatorRequest) => app().StartValidatorScan(request),
  startValidatorRangeScan: (request: ValidatorRangeRequest) => app().StartValidatorRangeScan(request),
  setValidatorPaused: (paused: boolean) => app().SetValidatorPaused(paused),
  cancelValidatorScan: () => app().CancelValidatorScan(),
  clearValidatorResults: () => app().ClearValidatorResults(),
  createResolverProfileFromValidatorResults: (request: ValidatorResolverProfileRequest) => app().CreateResolverProfileFromValidatorResults(request),
  listValidatorResultFiles: () => app().ListValidatorResultFiles(),
  openValidatorResultFile: (name: string) => app().OpenValidatorResultFile(name),
  deleteValidatorResultFile: (name: string) => app().DeleteValidatorResultFile(name),
  getScannerState: () => app().GetScannerState(),
  selectScannerInputFile: () => app().SelectScannerInputFile(),
  startScannerScan: (request: ScannerStartRequest) => app().StartScannerScan(request),
  setScannerPaused: (paused: boolean) => app().SetScannerPaused(paused),
  cancelScannerScan: () => app().CancelScannerScan(),
  clearScannerResults: () => app().ClearScannerResults(),
  saveScannerResolverProfile: (name: string) => app().SaveScannerResolverProfile(name),
  applyScannerConnectionUpgrade: (action: string) => app().ApplyScannerConnectionUpgrade(action),
  dismissScannerConnectionUpgrade: () => app().DismissScannerConnectionUpgrade(),
  exportClientToml: () => app().ExportClientToml(),
  exportConnectionProfileLink: (profile: ConnectionProfile) => app().ExportConnectionProfileLink(profile),
  exportAllConnectionProfileLinks: () => app().ExportAllConnectionProfileLinks(),
  exportSettingsProfileToml: (profile: SettingsProfile) => app().ExportSettingsProfileToml(profile),
  exportBackup: () => app().ExportBackup(),
  importBackup: (rawText: string) => app().ImportBackup(rawText),
  quit: () => app().Quit(),
};

let notificationInit: Promise<boolean> | null = null;

export function initializeNotifications(): Promise<boolean> {
  if (!notificationInit) {
    notificationInit = prepareNotifications();
  }
  return notificationInit;
}

export async function sendFirewallNotification(status: FirewallStatus): Promise<void> {
  const ready = await initializeNotifications();
  const runtime = window.runtime;
  if (!ready || !runtime?.SendNotification) {
    return;
  }

  try {
    await runtime.SendNotification({
      id: "whitedns-firewall-enabled",
      title: "Firewall is on",
      subtitle: status.name || undefined,
      body: status.message || "WhiteDNS may need local proxy/DNS traffic allowed.",
      data: {
        source: "firewall",
        name: status.name,
      },
    });
  } catch {
    // Notifications should never block or fail the connection flow.
  }
}

async function prepareNotifications(): Promise<boolean> {
  const runtime = window.runtime;
  if (!runtime?.InitializeNotifications || !runtime.IsNotificationAvailable) {
    return false;
  }

  try {
    const available = await runtime.IsNotificationAvailable();
    if (!available) {
      return false;
    }
    await runtime.InitializeNotifications();
    return ensureNotificationAuthorization(runtime);
  } catch {
    return false;
  }
}

async function ensureNotificationAuthorization(runtime: NonNullable<Window["runtime"]>): Promise<boolean> {
  if (!runtime.CheckNotificationAuthorization) {
    return true;
  }

  try {
    if (await runtime.CheckNotificationAuthorization()) {
      return true;
    }
  } catch {
    return true;
  }

  if (!runtime.RequestNotificationAuthorization) {
    return false;
  }

  try {
    return runtime.RequestNotificationAuthorization();
  } catch {
    return false;
  }
}

export function onRuntimeEvent<T>(eventName: string, callback: (payload: T) => void): () => void {
  const unsubscribe = window.runtime?.EventsOn(eventName, (...data: unknown[]) => {
    callback(data[0] as T);
  });
  return typeof unsubscribe === "function" ? unsubscribe : () => {};
}

export function openExternalUrl(url: string): void {
  if (window.runtime?.BrowserOpenURL) {
    window.runtime.BrowserOpenURL(url);
    return;
  }

  window.open(url, "_blank", "noopener,noreferrer");
}
