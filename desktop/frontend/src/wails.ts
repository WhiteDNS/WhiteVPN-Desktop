import type {
  AppState,
  CloudflarePingResult,
  FirewallStatus,
  ProxyCountryLookupResult,
  RuntimeType,
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
  ValidatorRequest,
  ValidatorResultFile,
  ValidatorState,
  LegacyImportOffer,
  WhiteVPNSettings,
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
  GetValidatorState(): Promise<ValidatorState>;
  GetDefaultValidatorRanges(): Promise<ValidatorRangeOption[]>;
  ParseValidatorRangeInput(rawText: string): Promise<ValidatorRangeImportResult>;
  StartValidatorScan(request: ValidatorRequest): Promise<ValidatorState>;
  StartValidatorRangeScan(request: ValidatorRangeRequest): Promise<ValidatorState>;
  SetValidatorPaused(paused: boolean): Promise<ValidatorState>;
  CancelValidatorScan(): Promise<ValidatorState>;
  ClearValidatorResults(): Promise<ValidatorState>;
  ListValidatorResultFiles(): Promise<ValidatorResultFile[]>;
  OpenValidatorResultFile(name: string): Promise<void>;
  DeleteValidatorResultFile(name: string): Promise<ValidatorResultFile[]>;
  GetWhiteVPNSettings(): Promise<WhiteVPNSettings>;
  SaveWhiteVPNSettings(settings: WhiteVPNSettings): Promise<AppState>;
  GetLegacyImportOffer(): Promise<LegacyImportOffer>;
  ImportLegacyProfiles(): Promise<AppState>;
  DismissLegacyImportOffer(): Promise<void>;
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
    throw new Error("WhiteVPN backend is not available. Run this UI inside Wails.");
  }
  return api;
}

export const backend = {
  getAppState: () => app().GetAppState(),
  checkFirewallStatus: () => app().CheckFirewallStatus(),
  getSystemLANIP: () => app().GetSystemLANIP(),
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
  startWhiteDNSVPNConnection: () => app().StartWhiteDNSVPNConnection(),
  refreshWhiteDNSVPNConnection: () => app().RefreshWhiteDNSVPNConnection(),
  saveWhiteDNSVPNFrontingIps: (rawText: string) => app().SaveWhiteDNSVPNFrontingIPs(rawText),
  startV2RayConnection: () => app().StartV2RayConnection(),
  stopConnection: () => app().StopConnection(),
  clearRuntimeLogs: (runtimeType: RuntimeType = "") => app().ClearRuntimeLogsForType(runtimeType),
  saveRuntimeLogs: (rawText: string) => app().SaveRuntimeLogs(rawText),
  pingCloudflare: () => app().PingCloudflare(),
  lookupProxyCountry: () => app().LookupProxyCountry(),
  getValidatorState: () => app().GetValidatorState(),
  getDefaultValidatorRanges: () => app().GetDefaultValidatorRanges(),
  parseValidatorRangeInput: (rawText: string) => app().ParseValidatorRangeInput(rawText),
  startValidatorScan: (request: ValidatorRequest) => app().StartValidatorScan(request),
  startValidatorRangeScan: (request: ValidatorRangeRequest) => app().StartValidatorRangeScan(request),
  setValidatorPaused: (paused: boolean) => app().SetValidatorPaused(paused),
  cancelValidatorScan: () => app().CancelValidatorScan(),
  clearValidatorResults: () => app().ClearValidatorResults(),
  listValidatorResultFiles: () => app().ListValidatorResultFiles(),
  openValidatorResultFile: (name: string) => app().OpenValidatorResultFile(name),
  deleteValidatorResultFile: (name: string) => app().DeleteValidatorResultFile(name),
  getWhiteVpnSettings: () => app().GetWhiteVPNSettings(),
  saveWhiteVpnSettings: (settings: WhiteVPNSettings) => app().SaveWhiteVPNSettings(settings),
  getLegacyImportOffer: () => app().GetLegacyImportOffer(),
  importLegacyProfiles: () => app().ImportLegacyProfiles(),
  dismissLegacyImportOffer: () => app().DismissLegacyImportOffer(),
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
