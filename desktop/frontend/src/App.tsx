import {
  Activity,
  AlertCircle,
  Check,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Globe,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  FileText,
  Gauge,
  ListChecks,
  Monitor,
  Moon,
  Pause,
  Plus,
  Play,
  Power,
  RotateCcw,
  Save,
  ScrollText,
  Search,
  Settings,
  Shield,
  Share2,
  SlidersHorizontal,
  Square,
  Sun,
  Trash2,
  Upload,
  Wifi,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import {
  Alert,
  AlertAction,
  AlertDescription,
  AlertTitle,
} from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldSet,
  FieldTitle,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Item,
  ItemContent,
  ItemDescription,
  ItemMedia,
  ItemTitle,
} from "@/components/ui/item";
import { Progress } from "@/components/ui/progress";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarSeparator,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useTheme, type Theme } from "@/components/theme-provider";
import { translate, normalizeLanguage, isRightToLeft, languages, type Language, type StringKey, type TranslateFn } from "./i18n";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

import type {
  AppState,
  ConnectionProfile,
  LegacyImportOffer,
  WhiteVPNSettings,
  DNSPrivacyMode,
  SplitTunnelMode,
  FirewallStatus,
  ImportType,
  RuntimeLogEntry,
  RuntimeStatus,
  RuntimeStatusName,
  ConnectionSelection,
  WhiteVPNNode,
  NodeTestRequest,
  RuntimeType,
  ValidatorEndpointInput,
  ValidatorOptions,
  ValidatorRangeOption,
  ValidatorResultFile,
  ValidatorState,
  SettingsProfile,
  V2RayProfile,
  V2RayPingResult,
  V2RayProtocol,
  V2RaySettingsProfile,
  V2RaySubscription,
} from "./types";
import { backend, initializeNotifications, onRuntimeEvent, openExternalUrl, sendFirewallNotification } from "./wails";

type Page = "vpn" | "servers" | "subscriptions" | "settings" | "engine-settings" | "logs" | "white-ips" | "validator" | "backup";
type NavItem = { id: Page; label: StringKey; icon: ReactNode };
type NavGroup = { id: "whitevpn" | "tools"; label: StringKey; items: NavItem[] };
type ValidatorStateUpdate = Omit<ValidatorState, "results"> & { results?: unknown; appendResults?: boolean };
type AppErrorToast = {
  id: number;
  message: string;
};

const runtimeLogLimit = 2000;
const defaultValidatorPort = 53;
const defaultValidatorRangePorts = [443, 2053, 2083, 2087, 2096, 8443];
const defaultValidatorRangeCSVName = "filtered_ipv4.csv";
const maxValidatorSelectedRangeHosts = 4000000;
const defaultValidatorWorkers = 128;
const maxValidatorWorkers = 2048;
const errorToastTTLMS = 6000;
const whiteDnsTelegramUrl = "https://t.me/whitedns";
// Mirrors the limits in internal/model/whitevpn_settings.go. Values outside them
// are repaired on save, so these only decide when a control stops accepting more.
const maxFrontingIPs = 5;
const minNoiseCount = 1;
const maxNoiseCount = 20;
const minNoiseSize = 1;
const maxNoiseSize = 1280;
const whiteDNSVPNSubscriptionID = "whitedns-vpn";
const enhancedConnectionLabel = "Enhanced Connection";
const iranRoutingDescription = [
  "Private/local IPs go direct, not through V2Ray.",
  "Iranian domains/IPs from geosite-ir and geoip-ir go direct.",
  "Ads, malware, phishing, cryptominers, and related bad IP/domain rule sets are blocked.",
  "Everything else still goes through the selected V2Ray proxy.",
  "Rule files are bundled with the app and loaded locally.",
].join("\n");
const defaultValidatorOptions: ValidatorOptions = {
  retries: 1,
  timeoutMillis: 600,
  workerCount: defaultValidatorWorkers,
  adaptiveLimit: defaultValidatorWorkers,
  httpPaths: ["/"],
  dnsQuestion: "cloudflare.com.",
  enableUdp: true,
  enableQuic: true,
  enableDns: true,
  enableWebSocket: true,
  allowInsecureCert: false,
};
function validatorWorkerCountOption(options: ValidatorOptions): number {
  return options.workerCount || options.adaptiveLimit || defaultValidatorOptions.workerCount;
}

function clampValidatorWorkers(value: number): number {
  if (!Number.isFinite(value)) {
    return defaultValidatorWorkers;
  }
  return Math.min(maxValidatorWorkers, Math.max(1, Math.round(value)));
}

function normalizeRuntime(runtime: RuntimeStatus): RuntimeStatus {
  const resolverState = runtime.resolverState || ({} as RuntimeStatus["resolverState"]);
  const runtimeType = normalizeRuntimeType(runtime.runtimeType);
  return {
    ...runtime,
    runtimeType,
    proxyProtocol: runtime.proxyProtocol === "http" ? "http" : runtime.proxyProtocol === "socks" ? "socks" : "",
    localProxyIp: runtime.localProxyIp || "",
    publicProxyIp: runtime.publicProxyIp || "",
    frontingIp: runtime.frontingIp || "",
    exitIp: runtime.exitIp || "",
    nodeName: runtime.nodeName || "",
    nodeCountryCode: runtime.nodeCountryCode || "",
    exitCountryCode: runtime.exitCountryCode || "",
    exitChecked: Boolean(runtime.exitChecked),
    autoProfilePresetId: runtime.autoProfilePresetId || "",
    autoProfileName: runtime.autoProfileName || "",
    resolverState: {
      ...resolverState,
      activeResolvers: Array.isArray(resolverState.activeResolvers) ? resolverState.activeResolvers : [],
      standbyResolvers: Array.isArray(resolverState.standbyResolvers) ? resolverState.standbyResolvers : [],
      validResolvers: Array.isArray(resolverState.validResolvers) ? resolverState.validResolvers : [],
      resolverDetails: Array.isArray(resolverState.resolverDetails) ? resolverState.resolverDetails : [],
    },
    trafficMonitorMessage: runtime.trafficMonitorMessage || "",
    logs: (Array.isArray(runtime.logs) ? runtime.logs : []).slice(0, runtimeLogLimit),
    masterDnsLogs: (Array.isArray(runtime.masterDnsLogs) ? runtime.masterDnsLogs : []).slice(0, runtimeLogLimit),
    v2rayLogs: (Array.isArray(runtime.v2rayLogs) ? runtime.v2rayLogs : []).slice(0, runtimeLogLimit),
  };
}

function normalizeRuntimeType(value?: string): RuntimeType {
  return value === "masterdns" || value === "v2ray" ? value : "";
}

function normalizeRuntimeLogEntry(value: RuntimeLogEntry | string): RuntimeLogEntry {
  if (typeof value === "string") {
    return { runtimeType: "", line: value };
  }
  return {
    runtimeType: normalizeRuntimeType(value?.runtimeType),
    line: value?.line || "",
  };
}

function normalizeImportType(value?: string): ImportType {
  return value === "stormdns" ? "stormdns" : "masterdns";
}

function normalizeConnectionProfile(profile: ConnectionProfile): ConnectionProfile {
  return {
    ...profile,
    importType: normalizeImportType(profile.importType),
  };
}

function normalizeV2RayProtocol(value?: string): V2RayProtocol {
  if (
    value === "vless" ||
    value === "vmess" ||
    value === "trojan" ||
    value === "shadowsocks" ||
    value === "hysteria2" ||
    value === "wireguard" ||
    value === "socks" ||
    value === "http"
  ) {
    return value;
  }
  return "vless";
}

function normalizeV2RayProfile(profile: V2RayProfile): V2RayProfile {
  return {
    ...profile,
    subscriptionId: profile.subscriptionId || "",
    protocol: normalizeV2RayProtocol(profile.protocol),
    serverPort: profile.serverPort || 443,
    network: profile.network || "tcp",
    security: profile.security || "auto",
    packetEncoding: profile.packetEncoding || "",
    echConfigList: profile.echConfigList || "",
    xhttpMode: profile.xhttpMode || "",
    xhttpExtra: profile.xhttpExtra || "",
    webSocketEarlyData: Math.max(0, Number(profile.webSocketEarlyData) || 0),
    webSocketEarlyDataHeader: profile.webSocketEarlyDataHeader || "",
    username: profile.username || "",
    shadowsocksMethod: profile.shadowsocksMethod || "2022-blake3-aes-256-gcm",
    uot: Boolean(profile.uot),
    uotVersion: Math.max(1, Number(profile.uotVersion) || 2),
    hysteriaAuth: profile.hysteriaAuth || "",
    hysteriaUdpIdleTimeout: Math.max(0, Number(profile.hysteriaUdpIdleTimeout) || 60),
    hysteriaMasquerade: profile.hysteriaMasquerade || "",
    httpHeaders: profile.httpHeaders || "",
    wireGuardSecretKey: profile.wireGuardSecretKey || "",
    wireGuardLocalAddresses: profile.wireGuardLocalAddresses || "10.0.0.2/32",
    wireGuardPeerPublicKey: profile.wireGuardPeerPublicKey || "",
    wireGuardPreSharedKey: profile.wireGuardPreSharedKey || "",
    wireGuardAllowedIps: profile.wireGuardAllowedIps || "0.0.0.0/0, ::/0",
    wireGuardKeepAlive: Math.max(0, Number(profile.wireGuardKeepAlive) || 0),
    wireGuardMtu: Math.max(0, Number(profile.wireGuardMtu) || 1420),
    wireGuardReserved: profile.wireGuardReserved || "",
    wireGuardNoKernelTun: normalizeV2RayProtocol(profile.protocol) === "wireguard" ? profile.wireGuardNoKernelTun !== false : Boolean(profile.wireGuardNoKernelTun),
    wireGuardDomainStrategy: profile.wireGuardDomainStrategy || "ForceIP",
    outboundSettings: profile.outboundSettings || "",
    streamSettings: profile.streamSettings || "",
  };
}

const v2rayProfileStableKeys: Array<keyof V2RayProfile> = [
  "id",
  "name",
  "subscriptionId",
  "protocol",
  "server",
  "serverPort",
  "uuid",
  "password",
  "alterId",
  "security",
  "flow",
  "packetEncoding",
  "network",
  "tls",
  "sni",
  "alpn",
  "allowInsecure",
  "utlsFingerprint",
  "echConfigList",
  "reality",
  "realityPublicKey",
  "realityShortId",
  "transportPath",
  "transportHost",
  "serviceName",
  "xhttpMode",
  "xhttpExtra",
  "webSocketEarlyData",
  "webSocketEarlyDataHeader",
  "username",
  "shadowsocksMethod",
  "uot",
  "uotVersion",
  "hysteriaAuth",
  "hysteriaUdpIdleTimeout",
  "hysteriaMasquerade",
  "httpHeaders",
  "wireGuardSecretKey",
  "wireGuardLocalAddresses",
  "wireGuardPeerPublicKey",
  "wireGuardPreSharedKey",
  "wireGuardAllowedIps",
  "wireGuardKeepAlive",
  "wireGuardMtu",
  "wireGuardReserved",
  "wireGuardNoKernelTun",
  "wireGuardDomainStrategy",
  "outboundSettings",
  "streamSettings",
];

function v2rayProfileNeedsNormalization(profile: V2RayProfile): boolean {
  return (
    (profile.subscriptionId || "") !== profile.subscriptionId ||
    normalizeV2RayProtocol(profile.protocol) !== profile.protocol ||
    !profile.serverPort ||
    !profile.network ||
    !profile.security ||
    (profile.packetEncoding || "") !== profile.packetEncoding ||
    (profile.echConfigList || "") !== profile.echConfigList ||
    (profile.xhttpMode || "") !== profile.xhttpMode ||
    (profile.xhttpExtra || "") !== profile.xhttpExtra ||
    Math.max(0, Number(profile.webSocketEarlyData) || 0) !== profile.webSocketEarlyData ||
    (profile.webSocketEarlyDataHeader || "") !== profile.webSocketEarlyDataHeader ||
    (profile.username || "") !== profile.username ||
    (profile.shadowsocksMethod || "2022-blake3-aes-256-gcm") !== profile.shadowsocksMethod ||
    Math.max(1, Number(profile.uotVersion) || 2) !== profile.uotVersion ||
    (profile.hysteriaAuth || "") !== profile.hysteriaAuth ||
    Math.max(0, Number(profile.hysteriaUdpIdleTimeout) || 60) !== profile.hysteriaUdpIdleTimeout ||
    (profile.hysteriaMasquerade || "") !== profile.hysteriaMasquerade ||
    (profile.httpHeaders || "") !== profile.httpHeaders ||
    (profile.wireGuardSecretKey || "") !== profile.wireGuardSecretKey ||
    (profile.wireGuardLocalAddresses || "10.0.0.2/32") !== profile.wireGuardLocalAddresses ||
    (profile.wireGuardPeerPublicKey || "") !== profile.wireGuardPeerPublicKey ||
    (profile.wireGuardPreSharedKey || "") !== profile.wireGuardPreSharedKey ||
    (profile.wireGuardAllowedIps || "0.0.0.0/0, ::/0") !== profile.wireGuardAllowedIps ||
    Math.max(0, Number(profile.wireGuardKeepAlive) || 0) !== profile.wireGuardKeepAlive ||
    Math.max(0, Number(profile.wireGuardMtu) || 1420) !== profile.wireGuardMtu ||
    (profile.wireGuardReserved || "") !== profile.wireGuardReserved ||
    (profile.wireGuardDomainStrategy || "ForceIP") !== profile.wireGuardDomainStrategy ||
    (profile.outboundSettings || "") !== profile.outboundSettings ||
    (profile.streamSettings || "") !== profile.streamSettings
  );
}

function normalizeV2RayProfilesForUI(profiles?: V2RayProfile[]): V2RayProfile[] {
  const items = Array.isArray(profiles) ? profiles : [];
  return items.some(v2rayProfileNeedsNormalization) ? items.map(normalizeV2RayProfile) : items;
}

function sameV2RayProfiles(left: V2RayProfile[], right: V2RayProfile[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((leftProfile, idx) => {
    const rightProfile = right[idx];
    return v2rayProfileStableKeys.every((key) => leftProfile[key] === rightProfile[key]);
  });
}

function normalizeV2RaySubscription(subscription: V2RaySubscription): V2RaySubscription {
  return {
    ...subscription,
    id: subscription.id || "",
    name: subscription.name || "V2Ray Subscription",
    url: subscription.url || "",
    lastUpdatedAt: subscription.lastUpdatedAt || "",
    lastError: subscription.lastError || "",
    importedCount: Math.max(0, Number(subscription.importedCount) || 0),
  };
}

function v2rayListenAllowsLan(value?: string): boolean {
  const trimmed = (value || "").trim();
  return trimmed === "0.0.0.0" || trimmed === "::";
}

function defaultV2RayTunInterfaceName(): string {
  const platform = `${navigator.platform || ""} ${navigator.userAgent || ""}`.toLowerCase();
  if (platform.includes("win")) {
    return "WhiteDNS Tunnel";
  }
  if (platform.includes("mac")) {
    return "utun20";
  }
  return "xray0";
}

function normalizeV2RaySettingsProfile(profile: V2RaySettingsProfile): V2RaySettingsProfile {
  const allowLan = Boolean(profile.allowLan) || v2rayListenAllowsLan(profile.listenIp);
  const missingTunSettings = !profile.tunEnabled && !profile.tunMtu && !profile.tunIpv6 && !profile.tunInterfaceName;
  return {
    ...profile,
    allowLan,
    listenIp: allowLan ? "0.0.0.0" : profile.listenIp || "127.0.0.1",
    listenPort: profile.listenPort || 10888,
    inboundType: profile.inboundType || "mixed",
    tunEnabled: Boolean(profile.tunEnabled),
    tunMtu: Math.max(576, Number(profile.tunMtu) || 1492),
    tunIpv6: missingTunSettings ? true : Boolean(profile.tunIpv6),
    tunInterfaceName: profile.tunInterfaceName || defaultV2RayTunInterfaceName(),
    iranRoutingEnabled: Boolean(profile.iranRoutingEnabled),
    logLevel: profile.logLevel || "WARN",
  };
}

function normalizeSettingsProfile(profile: SettingsProfile): SettingsProfile {
  const missingStartupLoss =
    !profile.mtuStartupLossVerifyEnabled &&
    !profile.mtuStartupLossVerifySamples &&
    !profile.mtuStartupLossVerifyMaxLossPercent &&
    !profile.mtuStartupLossVerifyCandidates;
  const missingRecheck = !profile.mtuRecheckEnabled && !profile.mtuRecheckIntervalMinutes;
  return {
    ...profile,
    importType: normalizeImportType(profile.importType),
    connectionStartupMode: profile.connectionStartupMode === "full-scan" ? "full-scan" : "standard",
    mtuStartupLossVerifyEnabled: missingStartupLoss ? true : profile.mtuStartupLossVerifyEnabled,
    mtuStartupLossVerifySamples: profile.mtuStartupLossVerifySamples || 3,
    mtuStartupLossVerifyMaxLossPercent: profile.mtuStartupLossVerifyMaxLossPercent ?? 34,
    mtuStartupLossVerifyCandidates: profile.mtuStartupLossVerifyCandidates || 3,
    mtuRecheckEnabled: missingRecheck ? true : profile.mtuRecheckEnabled,
    mtuRecheckIntervalMinutes: profile.mtuRecheckIntervalMinutes ?? 5,
  };
}

function normalizeAppState(state: AppState, previous?: AppState | null): AppState {
  const next = {
    ...state,
    connectionProfiles: (state.connectionProfiles || []).map(normalizeConnectionProfile),
    settingsProfiles: (state.settingsProfiles || []).map(normalizeSettingsProfile),
    v2rayProfiles: normalizeV2RayProfilesForUI(state.v2rayProfiles),
    v2raySubscriptions: (state.v2raySubscriptions || []).map(normalizeV2RaySubscription),
    v2raySettingsProfiles: (state.v2raySettingsProfiles || []).map(normalizeV2RaySettingsProfile),
    whiteDNSVPNFrontingIps: Array.isArray(state.whiteDNSVPNFrontingIps) ? state.whiteDNSVPNFrontingIps : [],
    runtime: normalizeRuntime(state.runtime),
  };
  if (previous?.v2rayProfiles && sameV2RayProfiles(previous.v2rayProfiles, next.v2rayProfiles)) {
    next.v2rayProfiles = previous.v2rayProfiles;
  }
  return next;
}

function profileSelectionLocked(runtime: RuntimeStatus): boolean {
  return runtime.status !== "disconnected" && runtime.status !== "failed";
}

function runtimeTypeForState(state: AppState): RuntimeType {
  const explicit = normalizeRuntimeType(state.runtime.runtimeType);
  if (explicit) {
    return explicit;
  }
  const activeId = state.runtime.activeConnectionId;
  if (!activeId) {
    return "";
  }
  if (state.v2rayProfiles.some((profile) => profile.id === activeId)) {
    return "v2ray";
  }
  if (state.connectionProfiles.some((profile) => profile.id === activeId)) {
    return "masterdns";
  }
  return "";
}

function v2RayRuntimeActive(state: AppState): boolean {
  return runtimeTypeForState(state) === "v2ray";
}

function whiteDNSVPNRuntimeActive(state: AppState): boolean {
  // A mihomo session connects straight from the subscription and stores no
  // profile, so there is no activeConnectionId to match. Recognising it by its
  // engine is what stops the app reporting its own working connection as
  // belonging to something else.
  if (state.runtime.engine === "mihomo") {
    return true;
  }
  return v2RayRuntimeActive(state) && state.v2rayProfiles.some((profile) => (
    profile.id === state.runtime.activeConnectionId && profile.subscriptionId === whiteDNSVPNSubscriptionID
  ));
}

function makeV2RaySettingsProfileId(profiles: V2RaySettingsProfile[]): string {
  const existing = new Set(profiles.map((profile) => profile.id));
  const base = `v2ray-settings-${Date.now()}`;
  let id = base;
  for (let attempt = 1; existing.has(id); attempt += 1) {
    id = `${base}-${attempt}`;
  }
  return id;
}

function effectiveV2RaySettingsProfile(state: AppState): V2RaySettingsProfile | undefined {
  return (
    state.v2raySettingsProfiles.find((profile) => profile.id === state.selectedV2RaySettingsId) ||
    state.v2raySettingsProfiles[0]
  );
}

function proxyEndpoint(ip?: string, port?: number): string {
  return ip && port ? `${ip}:${port}` : "";
}

function runtimeProxyDisplayEndpoint(runtime: RuntimeStatus): string {
  return (
    proxyEndpoint(runtime.publicProxyIp, runtime.listenPort) ||
    proxyEndpoint(runtime.localProxyIp, runtime.listenPort) ||
    proxyEndpoint(runtime.listenIp, runtime.listenPort)
  );
}

function downloadTextFile(filename: string, text: string, mimeType = "text/plain;charset=utf-8"): void {
  const blob = new Blob([text], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function countWhiteIPEndpointLines(text: string): number {
  return text
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith(";") && !(line.startsWith("[") && line.endsWith("]")))
    .length;
}

const defaultValidatorState: ValidatorState = {
  status: "idle",
  paused: false,
  mode: "quick",
  total: 0,
  completed: 0,
  retained: 0,
  ready: 0,
  bestScore: 0,
  gradeAPlus: 0,
  gradeA: 0,
  gradeB: 0,
  gradeC: 0,
  gradeF: 0,
  ports: [],
  results: [],
  resultsFileName: "",
  resultsFilePath: "",
  resultsFileRows: 0,
  resultsFilePart: 0,
  resultsFileCount: 0,
  requestedWorkers: defaultValidatorWorkers,
  effectiveWorkers: defaultValidatorWorkers,
  workerCeiling: defaultValidatorWorkers,
  pressureEvents: 0,
  error: "",
  startedAt: 0,
  finishedAt: 0,
  options: defaultValidatorOptions,
};

function normalizeValidatorState(next: ValidatorStateUpdate, current: ValidatorState = defaultValidatorState): ValidatorState {
  return {
    ...current,
    ...next,
    appendResults: false,
    results: [],
    ports: Array.isArray(next.ports) ? next.ports : current.ports || [],
    options: {
      ...defaultValidatorOptions,
      ...(current.options || {}),
      ...(next.options || {}),
    },
  };
}

const navGroups: NavGroup[] = [
  {
    id: "whitevpn",
    label: "nav.group.whitevpn",
    items: [
      { id: "vpn", label: "nav.vpn", icon: <Power /> },
      { id: "servers", label: "nav.servers", icon: <Shield /> },
      { id: "subscriptions", label: "nav.subscriptions", icon: <ListChecks /> },
      { id: "settings", label: "nav.settings", icon: <Settings /> },
      { id: "logs", label: "nav.logs", icon: <ScrollText /> },
    ],
  },
  {
    id: "tools",
    label: "nav.group.tools",
    items: [
      { id: "white-ips", label: "nav.whiteIps", icon: <Share2 /> },
      { id: "validator", label: "nav.validator", icon: <ListChecks /> },
      { id: "backup", label: "nav.backup", icon: <Save /> },
    ],
  },
];

// useLanguage resolves the stored setting and keeps the document's direction in
// step with it.
function useLanguage(state: AppState | null): { language: Language; t: TranslateFn } {
  const language = normalizeLanguage(state?.whiteVpn?.language ?? "");

  useEffect(() => {
    const root = document.documentElement;
    root.lang = language;
    // On the document, not a wrapper: dialogs and toasts render outside the page
    // tree and would otherwise stay left-to-right inside a right-to-left app.
    root.dir = isRightToLeft(language) ? "rtl" : "ltr";
  }, [language]);

  const t = useMemo<TranslateFn>(() => (key, params) => translate(language, key, params), [language]);
  return { language, t };
}

function App() {
  const [state, setState] = useState<AppState | null>(null);
  const { language, t } = useLanguage(state);
  const [legacyOffer, setLegacyOffer] = useState<LegacyImportOffer | null>(null);
  // Null until the backend has been asked, so the gate is never shown or hidden
  // on a guess.
  const [policyVersion, setPolicyVersion] = useState<number | null>(null);
  const [page, setPage] = useState<Page>("vpn");
  const [errorToast, setErrorToast] = useState<AppErrorToast | null>(null);
  const [successToast, setSuccessToast] = useState<AppErrorToast | null>(null);
  const [validatorState, setValidatorState] = useState<ValidatorState>(defaultValidatorState);
  // One catalogue, shared. The dashboard dialog picks from it and the Servers
  // page tests it; two fetches would be two lists that drift.
  const [nodes, setNodes] = useState<WhiteVPNNode[]>([]);
  const [nodesLoading, setNodesLoading] = useState(false);
  const [nodeTestRunning, setNodeTestRunning] = useState(false);
  const runtimeLogBufferRef = useRef<RuntimeLogEntry[]>([]);
  const runtimeLogFlushTimerRef = useRef<number | null>(null);

  function applyState(next: AppState) {
    setState((current) => normalizeAppState(next, current));
  }

  function applyValidatorState(next: ValidatorStateUpdate) {
    setValidatorState((current) => normalizeValidatorState(next, current));
  }

  function showError(message: string) {
    if (!message) {
      setErrorToast(null);
      return;
    }
    setSuccessToast(null);
    setErrorToast((current) => ({ id: current ? current.id + 1 : 1, message }));
  }

  function showSuccess(message: string) {
    if (!message) {
      setSuccessToast(null);
      return;
    }
    setErrorToast(null);
    setSuccessToast((current) => ({ id: current ? current.id + 1 : 1, message }));
  }

  // Only once both halves are known: the version the app asks for, and what the
  // state says was accepted.
  const policyNeeded =
    policyVersion !== null && policyVersion > 0 && (state?.whiteVpn.acceptedPrivacyPolicyVersion ?? 0) < policyVersion;

  async function acceptPrivacyPolicy() {
    try {
      applyState(await backend.acceptPrivacyPolicy());
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  async function loadNodes(refresh: boolean) {
    setNodesLoading(true);
    try {
      const list = await backend.listWhiteVpnNodes(refresh);
      setNodes(list.nodes || []);
    } catch (err) {
      showError(messageFromError(err));
    } finally {
      setNodesLoading(false);
    }
  }

  async function runNodeTest(request: NodeTestRequest) {
    try {
      setNodeTestRunning(true);
      await backend.startNodeTest(request);
    } catch (err) {
      setNodeTestRunning(false);
      showError(messageFromError(err));
    }
  }

  async function cancelNodeTest() {
    try {
      await backend.cancelNodeTest();
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  // Picking a node from the Servers page means the same thing as picking one in
  // the dashboard dialog, and goes through the same call, so a live connection
  // follows it there too.
  async function useNode(name: string) {
    if (!state) {
      return;
    }
    try {
      applyState(await backend.saveWhiteVpnSelection(state.whiteVpn.countryCode, { ...state.whiteVpn.connection, node: name }));
      showSuccess(name);
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  function clearErrorToast() {
    setErrorToast(null);
  }

  function clearSuccessToast() {
    setSuccessToast(null);
  }

  useEffect(() => {
    void initializeNotifications();
    backend
      .getAppState()
      .then(applyState)
      .catch((err) => showError(messageFromError(err)));
    backend
      .getPrivacyPolicyVersion()
      .then(setPolicyVersion)
      .catch(() => setPolicyVersion(0));
    backend
      .getLegacyImportOffer()
      .then((offer) => setLegacyOffer(offer?.available ? offer : null))
      .catch(() => setLegacyOffer(null));
    backend
      .getValidatorState()
      .then(applyValidatorState)
      .catch((err) => showError(messageFromError(err)));

    const flushRuntimeLogs = () => {
      const batch = runtimeLogBufferRef.current.splice(0);
      runtimeLogFlushTimerRef.current = null;
      if (!batch.length) {
        return;
      }
      setState((current) => {
        if (!current) {
          return current;
        }
        let logs = Array.isArray(current.runtime.logs) ? current.runtime.logs : [];
        let masterDnsLogs = Array.isArray(current.runtime.masterDnsLogs) ? current.runtime.masterDnsLogs : [];
        let v2rayLogs = Array.isArray(current.runtime.v2rayLogs) ? current.runtime.v2rayLogs : [];
        for (const entry of batch) {
          const line = entry.line;
          if (!line) {
            continue;
          }
          const runtimeType = entry.runtimeType || runtimeTypeForState(current);
          logs = [line, ...logs].slice(0, runtimeLogLimit);
          if (runtimeType === "masterdns") {
            masterDnsLogs = [line, ...masterDnsLogs].slice(0, runtimeLogLimit);
          } else if (runtimeType === "v2ray") {
            v2rayLogs = [line, ...v2rayLogs].slice(0, runtimeLogLimit);
          }
        }
        return {
          ...current,
          runtime: {
            ...current.runtime,
            logs,
            masterDnsLogs,
            v2rayLogs,
          },
        };
      });
    };

    const unsubscribers = [
      onRuntimeEvent<RuntimeStatus>("runtime:state", (runtime) => {
        setState((current) => (current ? { ...current, runtime: normalizeRuntime(runtime) } : current));
      }),
      onRuntimeEvent<RuntimeLogEntry | string>("runtime:log", (entry) => {
        runtimeLogBufferRef.current.push(normalizeRuntimeLogEntry(entry));
        if (runtimeLogFlushTimerRef.current === null) {
          runtimeLogFlushTimerRef.current = window.setTimeout(flushRuntimeLogs, 250);
        }
      }),
      onRuntimeEvent<WhiteVPNNode>("nodes:test", (node) => {
        setNodes((current) => current.map((entry) => (entry.name === node.name ? node : entry)));
      }),
      onRuntimeEvent<unknown>("nodes:test-done", () => setNodeTestRunning(false)),
      onRuntimeEvent<string>("nodes:test-error", (message) => {
        setNodeTestRunning(false);
        showError(message);
      }),
      onRuntimeEvent<AppState>("app:state", applyState),
      onRuntimeEvent<ValidatorStateUpdate>("validator:state", applyValidatorState),
      onRuntimeEvent<ValidatorStateUpdate>("validator:progress", applyValidatorState),
      onRuntimeEvent<string>("runtime:error", showError),
      onRuntimeEvent<FirewallStatus>("firewall:enabled", (status) => {
        void sendFirewallNotification(status);
      }),
    ];

    return () => {
      unsubscribers.forEach((unsubscribe) => unsubscribe());
      if (runtimeLogFlushTimerRef.current !== null) {
        window.clearTimeout(runtimeLogFlushTimerRef.current);
        runtimeLogFlushTimerRef.current = null;
      }
      runtimeLogBufferRef.current = [];
    };
  }, []);

  useEffect(() => {
    if (!errorToast) {
      return;
    }

    const timer = window.setTimeout(() => {
      setErrorToast((current) => (current?.id === errorToast.id ? null : current));
    }, errorToastTTLMS);

    return () => window.clearTimeout(timer);
  }, [errorToast]);

  useEffect(() => {
    if (!successToast) {
      return;
    }

    const timer = window.setTimeout(() => {
      setSuccessToast((current) => (current?.id === successToast.id ? null : current));
    }, errorToastTTLMS);

    return () => window.clearTimeout(timer);
  }, [successToast]);

  async function acceptLegacyImport() {
    setLegacyOffer(null);
    try {
      applyState(await backend.importLegacyProfiles());
      showSuccess("Imported your WhiteDNS Desktop profiles.");
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  async function declineLegacyImport() {
    setLegacyOffer(null);
    try {
      await backend.dismissLegacyImportOffer();
    } catch {
      // Declining is only a session-level preference; a failure here is not
      // worth interrupting startup for.
    }
  }

  // The Servers page is useless without the catalogue; one load serves it and
  // the dashboard dialog both. Above the early return below, because it is a
  // hook and hooks cannot be conditional.
  useEffect(() => {
    if (page === "servers" && !nodes.length && !nodesLoading) {
      void loadNodes(false);
    }
  }, [page]);

  if (!state) {
    return (
      <>
        <LoadingView t={t} />
        <ErrorToast toast={errorToast} onDismiss={clearErrorToast} />
        <SuccessToast toast={successToast} onDismiss={clearSuccessToast} />
      </>
    );
  }

  const activePage = page;

  return (
    <TooltipProvider>
      <SidebarProvider defaultOpen>
        <AppSidebar page={activePage} runtime={state.runtime} onPage={setPage} language={language} t={t} />
        <SidebarInset className="min-w-0 overflow-x-hidden">
          <main className="min-h-svh min-w-0 overflow-x-hidden bg-muted/30 p-4 md:p-6">
            <div className="mx-auto flex w-full min-w-0 max-w-7xl flex-col gap-4">
              <div className="flex items-center justify-between gap-2 md:hidden">
                <div className="flex min-w-0 items-center gap-2">
                  <SidebarTrigger />
                  <AppIcon className="size-7" />
                  <span className="min-w-0 truncate text-sm font-medium">WhiteVPN</span>
                </div>
                <ThemeSettingsMenu />
              </div>

              <ErrorToast toast={errorToast} onDismiss={clearErrorToast} />
              <SuccessToast toast={successToast} onDismiss={clearSuccessToast} />

              {activePage === "vpn" && (
                <WhiteDNSVPNPage state={state} onState={applyState} onError={showError} onNavigate={setPage} language={language} t={t} />
              )}

              {activePage === "servers" && (
                <NodesPage
                  state={state}
                  nodes={nodes}
                  loading={nodesLoading}
                  testing={nodeTestRunning}
                  onReload={() => void loadNodes(true)}
                  onRunTest={(request) => void runNodeTest(request)}
                  onCancelTest={() => void cancelNodeTest()}
                  onSelectNode={(name) => void useNode(name)}
                  onError={showError}
                  onSuccess={showSuccess}
                  language={language}
                  t={t}
                />
              )}

              {activePage === "subscriptions" && (
                <V2RaySubscriptionsPage
                  state={state}
                  onState={applyState}
                  onError={showError}
                  onSuccess={showSuccess}
                  t={t}
                />
              )}

              {activePage === "settings" && (
                <WhiteVPNSettingsPage
                  state={state}
                  onState={applyState}
                  onError={showError}
                  onSuccess={showSuccess}
                  onNavigate={setPage}
                  t={t}
                />
              )}

              {activePage === "engine-settings" && (
                <V2RaySettingsPage state={state} onState={applyState} onError={showError} />
              )}

              {activePage === "logs" && <LogsPage runtime={state.runtime} runtimeType="v2ray" onState={applyState} onError={showError} />}

              {activePage === "white-ips" && (
                <V2RayWhiteIPsPage onState={applyState} onError={showError} onSuccess={showSuccess} />
              )}

              {activePage === "validator" && (
                <ValidatorPage state={validatorState} onState={applyValidatorState} onAppState={applyState} onError={showError} />
              )}

              {activePage === "backup" && (
                <FullBackupPage state={state} onState={applyState} onError={showError} onSuccess={showSuccess} />
              )}

            </div>
          </main>
        </SidebarInset>

        {policyNeeded ? (
          <PrivacyPolicyGate onAccept={acceptPrivacyPolicy} onQuit={() => void backend.quit()} t={t} />
        ) : (
          <LegacyImportDialog
            offer={legacyOffer}
            onImport={acceptLegacyImport}
            onDismiss={declineLegacyImport}
          />
        )}
      </SidebarProvider>
    </TooltipProvider>
  );
}

function ErrorToast({ toast, onDismiss }: { toast: AppErrorToast | null; onDismiss: () => void }) {
  if (!toast) {
    return null;
  }

  return (
    <div className="fixed top-4 end-4 start-4 z-[100] sm:top-6 sm:end-6 sm:start-auto sm:w-full sm:max-w-md">
      <Alert variant="destructive" className="border-destructive/25 shadow-lg">
        <AlertCircle />
        <AlertTitle>Operation failed</AlertTitle>
        <AlertDescription>{toast.message}</AlertDescription>
        <AlertAction>
          <Button variant="ghost" size="icon-sm" onClick={onDismiss} aria-label="Dismiss">
            <X />
          </Button>
        </AlertAction>
      </Alert>
    </div>
  );
}

function SuccessToast({ toast, onDismiss }: { toast: AppErrorToast | null; onDismiss: () => void }) {
  if (!toast) {
    return null;
  }

  return (
    <div className="fixed top-4 end-4 start-4 z-[100] sm:top-6 sm:end-6 sm:start-auto sm:w-full sm:max-w-md">
      <Alert className="border-emerald-200 bg-emerald-50 text-emerald-950 shadow-lg dark:border-emerald-900/60 dark:bg-emerald-950 dark:text-emerald-100">
        <CheckCircle2 />
        <AlertTitle>{toast.message}</AlertTitle>
        <AlertAction>
          <Button variant="ghost" size="icon-sm" onClick={onDismiss} aria-label="Dismiss">
            <X />
          </Button>
        </AlertAction>
      </Alert>
    </div>
  );
}

function ThemeSettingsMenu({ className, sidebar = false }: { className?: string; sidebar?: boolean }) {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }

    function onPointerDown(event: PointerEvent) {
      if (!menuRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
      }
    }

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  function chooseTheme(nextTheme: Theme) {
    setTheme(nextTheme);
    setOpen(false);
  }

  return (
    <div ref={menuRef} className={cn("relative shrink-0", className)}>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        aria-label="Open appearance settings"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
        className={cn(
          sidebar &&
            "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground aria-expanded:bg-sidebar-accent aria-expanded:text-sidebar-accent-foreground",
        )}
      >
        <Settings />
      </Button>
      {open && (
        <div
          role="menu"
          aria-label="Theme"
          className="absolute end-0 top-[calc(100%+0.375rem)] z-50 w-52 overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <div className="flex items-center justify-between gap-2 px-2 py-1.5 text-sm font-medium">
            <span>Theme</span>
            <span className="rounded-sm bg-muted px-1.5 py-0.5 text-[0.65rem] font-normal uppercase leading-none text-muted-foreground">
              {resolvedTheme}
            </span>
          </div>
          <ThemeMenuItem
            icon={<Sun />}
            label="Light"
            active={theme === "light"}
            onSelect={() => chooseTheme("light")}
          />
          <ThemeMenuItem
            icon={<Moon />}
            label="Dark"
            active={theme === "dark"}
            onSelect={() => chooseTheme("dark")}
          />
          <ThemeMenuItem
            icon={<Monitor />}
            label="System"
            active={theme === "system"}
            onSelect={() => chooseTheme("system")}
          />
        </div>
      )}
    </div>
  );
}

function ThemeMenuItem({
  icon,
  label,
  active,
  onSelect,
}: {
  icon: ReactNode;
  label: string;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitemradio"
      aria-checked={active}
      onClick={onSelect}
      className={cn(
        "relative flex w-full items-center gap-2 rounded-sm py-1.5 pe-2 ps-8 text-start text-sm outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:bg-accent focus-visible:text-accent-foreground [&_svg]:size-4 [&_svg]:shrink-0",
        active && "bg-accent text-accent-foreground",
      )}
    >
      <span className="absolute start-2 flex size-3.5 items-center justify-center">
        {active && <CheckCircle2 className="size-3.5" />}
      </span>
      {icon}
      <span>{label}</span>
    </button>
  );
}

function AppSidebar({
  page,
  runtime,
  onPage,
  language,
  t,
}: {
  page: Page;
  runtime: RuntimeStatus;
  onPage: (page: Page) => void;
  language: Language;
  t: TranslateFn;
}) {
  const sidebarEndpoint = runtimeProxyDisplayEndpoint(runtime);
  const [openGroups, setOpenGroups] = useState<Record<NavGroup["id"], boolean>>({
    whitevpn: true,
    tools: true,
  });

  function toggleGroup(groupId: NavGroup["id"]) {
    setOpenGroups((current) => ({
      ...current,
      [groupId]: !current[groupId],
    }));
  }

  return (
    // The sidebar reserves its space with an in-flow element and then pins
    // itself with `position: fixed; left: 0`. Under a right-to-left document
    // the reserved space moves to the right while the pin does not, so the
    // sidebar lands on top of the page. Telling it which side it is on is what
    // keeps the two together — and in a right-to-left layout the navigation
    // belongs on the right anyway.
    <Sidebar collapsible="icon" variant="sidebar" side={isRightToLeft(language) ? "right" : "left"}>
      <SidebarHeader>
        <div className="flex items-center justify-between gap-2 px-2 py-2">
          <div className="flex min-w-0 items-center gap-2.5">
            <div className="grid size-9 shrink-0 place-items-center overflow-hidden rounded-lg border bg-background">
              <AppIcon className="size-8" />
            </div>
            <div className="min-w-0 group-data-[collapsible=icon]:hidden">
              <div className="truncate text-sm leading-snug font-medium">WhiteVPN</div>
              <p className="truncate text-sm leading-normal text-muted-foreground">v1.0.0</p>
            </div>
          </div>
          <ThemeSettingsMenu
            sidebar
            className="ms-auto group-data-[collapsible=icon]:hidden"
          />
        </div>
        <a
          href={whiteDnsTelegramUrl}
          target="_blank"
          rel="noopener noreferrer"
          aria-label="Open WhiteDNS Telegram channel"
          onClick={(event) => {
            event.preventDefault();
            openExternalUrl(whiteDnsTelegramUrl);
          }}
          className="mx-2 flex h-8 items-center justify-between gap-2 rounded-md px-2 text-xs font-medium text-sidebar-foreground/70 ring-sidebar-ring transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 focus-visible:outline-hidden group-data-[collapsible=icon]:hidden"
        >
          <span className="truncate">{t("nav.source")}</span>
          <ExternalLink className="size-3.5 shrink-0" aria-hidden="true" />
        </a>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            {navGroups.map((group, index) => {
              const isOpen = openGroups[group.id];

              return (
                <div key={group.id}>
                  {index > 0 && (
                    <Separator className="mx-2 my-1 w-auto bg-sidebar-border group-data-[collapsible=icon]:hidden" />
                  )}
                  <SidebarGroupLabel
                    asChild
                    className="h-7 cursor-pointer justify-between text-sm font-semibold text-sidebar-foreground"
                  >
                    <button type="button" aria-expanded={isOpen} onClick={() => toggleGroup(group.id)}>
                      <span className="truncate">{t(group.label)}</span>
                      {isOpen ? (
                        <ChevronDown className="ms-auto size-3.5 shrink-0" aria-hidden="true" />
                      ) : (
                        <ChevronRight className="ms-auto size-3.5 shrink-0 rtl:rotate-180" aria-hidden="true" />
                      )}
                    </button>
                  </SidebarGroupLabel>

                  {isOpen && (
                    <SidebarMenu className="mt-1">
                      {group.items.map((item) => (
                        <SidebarMenuItem key={item.id}>
                          <SidebarMenuButton
                            isActive={page === item.id}
                            tooltip={t(item.label)}
                            onClick={() => onPage(item.id)}
                          >
                            {item.icon}
                            <span>{t(item.label)}</span>
                          </SidebarMenuButton>
                        </SidebarMenuItem>
                      ))}
                    </SidebarMenu>
                  )}
                </div>
              );
            })}
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarSeparator />
      <SidebarFooter>
        <Item className="border-transparent bg-muted/50">
          <ItemMedia>
            <StatusDot status={runtime.status} />
          </ItemMedia>
          <ItemContent>
            <ItemTitle>{translatedStatusLabel(t, runtime.status)}</ItemTitle>
            <ItemDescription className="line-clamp-none">
              <span className="block">
                {sidebarEndpoint || t("status.noActiveProxy")}
              </span>
            </ItemDescription>
          </ItemContent>
        </Item>
      </SidebarFooter>
    </Sidebar>
  );
}

function AppIcon({ className }: { className?: string }) {
  return (
    <img
      src="/icon-192.png"
      alt=""
      aria-hidden="true"
      className={cn("shrink-0 rounded-[6px] object-contain", className)}
    />
  );
}

// Shown before there is any state, so the language is the one the system says.
function LoadingView({ t }: { t: TranslateFn }) {
  return (
    <main className="grid min-h-svh place-items-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>WhiteVPN Desktop</CardTitle>
          <CardDescription>{t("nav.loading")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-4/5" />
          <Skeleton className="h-8 w-3/5" />
        </CardContent>
      </Card>
    </main>
  );
}

// The connect button's five states, as WhiteVPN for Android has them. It is one
// control throughout — the same button stops a connection it started, and stops
// one still being made — so its state is the page's state, and the card above it
// follows from this rather than deciding for itself.
type ConnectButtonState = "connect" | "connecting" | "disconnect" | "disconnecting" | "retry";

// pendingAction bridges the gap between a click and the backend's answer. The
// backend reports "stopping" and "connecting" itself, so this only covers the
// moment before the first of those arrives.
type PendingAction = "start" | "stop" | null;

function connectButtonState(status: RuntimeStatusName, pending: PendingAction): ConnectButtonState {
  switch (status) {
    case "stopping":
      return "disconnecting";
    // A stop is answered by a status change, but not in the same frame. Until
    // it arrives the button says what was asked of it.
    case "connecting":
      return pending === "stop" ? "disconnecting" : "connecting";
    case "connected":
      return pending === "stop" ? "disconnecting" : "disconnect";
    case "failed":
      return pending === "start" ? "connecting" : "retry";
    default:
      return pending === "start" ? "connecting" : "connect";
  }
}

// The card's state is the button's state. Anything else and the two can
// disagree, which is how a card once said connected next to a Connect button.
function connectCardStatus(connectState: ConnectButtonState): RuntimeStatusName {
  switch (connectState) {
    case "connecting":
      return "connecting";
    case "disconnecting":
      return "stopping";
    case "disconnect":
      return "connected";
    case "retry":
      return "failed";
    default:
      return "disconnected";
  }
}

// A flag from a country code: the same two letters, moved into the regional
// indicator block. Building it from the code rather than keeping the one the
// node name carried means every row shows one, including the country list,
// which has codes and no names to take a flag from.
function flagFromCountryCode(code: string): string {
  if (code.length !== 2) {
    return "";
  }
  const base = 0x1f1e6;
  return String.fromCodePoint(base + (code.charCodeAt(0) - 65), base + (code.charCodeAt(1) - 65));
}

// Country names come from the platform, in the app's own language, so there is
// no table of two hundred and fifty countries here to fall out of step with the
// catalogue.
function countryName(code: string, language: Language, unknown: string): string {
  if (!code) {
    return unknown;
  }
  try {
    return new Intl.DisplayNames([language], { type: "region" }).of(code) || code;
  } catch {
    return code;
  }
}

type CountryOption = { code: string; count: number; name: string };

function countryOptions(nodes: WhiteVPNNode[], language: Language, unknown: string): CountryOption[] {
  const counts = new Map<string, number>();
  for (const node of nodes) {
    if (!node.countryCode) {
      continue;
    }
    counts.set(node.countryCode, (counts.get(node.countryCode) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([code, count]) => ({ code, count, name: countryName(code, language, unknown) }))
    .sort((a, b) => a.name.localeCompare(b.name, language));
}

// A dashboard row: a label, what it is currently set to, and a dialog behind it.
function DashboardRow({
  icon,
  label,
  value,
  disabled,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="flex w-full items-center justify-between gap-3 rounded-md border bg-background/70 px-3 py-2.5 text-start transition-colors hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-60"
    >
      <span className="flex shrink-0 items-center gap-2 text-muted-foreground">
        {icon}
        <span className="text-sm font-medium text-foreground">{label}</span>
      </span>
      <span className="flex min-w-0 items-center gap-2">
        <span className="min-w-0 truncate text-sm text-muted-foreground">{value}</span>
        <ChevronRight className="size-4 shrink-0 text-muted-foreground rtl:rotate-180" />
      </span>
    </button>
  );
}

function SelectableRow({
  selected,
  onClick,
  children,
}: {
  selected: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex w-full items-center justify-between gap-3 rounded-md border px-3 py-2 text-start transition-colors hover:bg-muted/60",
        selected ? "border-emerald-500/60 bg-emerald-500/10" : "bg-background/60"
      )}
    >
      <span className="flex min-w-0 flex-1 items-center gap-2">{children}</span>
      {selected && <Check className="size-4 shrink-0 text-emerald-600" />}
    </button>
  );
}

function LocationDialog({
  open,
  nodes,
  selected,
  busy,
  loading,
  language,
  t,
  onOpenChange,
  onSelect,
}: {
  open: boolean;
  nodes: WhiteVPNNode[];
  selected: string;
  busy: boolean;
  loading: boolean;
  language: Language;
  t: TranslateFn;
  onOpenChange: (open: boolean) => void;
  onSelect: (countryCode: string) => void;
}) {
  const unknown = t("vpn.nodes.unknownCountry");
  const countries = useMemo(() => countryOptions(nodes, language, unknown), [nodes, language, unknown]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100svh-4rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("vpn.location.title")}</DialogTitle>
          <DialogDescription>{t("vpn.location.description")}</DialogDescription>
        </DialogHeader>
        <ScrollArea className="min-h-0">
          <div className="grid gap-1.5 pe-3">
            <SelectableRow selected={!selected} onClick={() => onSelect("")}>
              <span className="text-sm font-medium">{t("vpn.automatic")}</span>
              <span className="text-xs text-muted-foreground">
                {nodes.length} {t("vpn.nodes.count")}
              </span>
            </SelectableRow>
            {countries.map((country) => (
              <SelectableRow key={country.code} selected={selected === country.code} onClick={() => onSelect(country.code)}>
                <span className="text-base leading-none">{flagFromCountryCode(country.code)}</span>
                <span className="min-w-0 flex-1 truncate text-sm">{country.name}</span>
                <span className="text-xs text-muted-foreground">
                  {country.count} {t("vpn.nodes.count")}
                </span>
              </SelectableRow>
            ))}
            {!countries.length && (
              <p className="px-1 py-6 text-center text-sm text-muted-foreground">
                {loading ? t("vpn.nodes.loading") : t("vpn.nodes.none")}
              </p>
            )}
          </div>
          <ScrollBar orientation="vertical" />
        </ScrollArea>
        <DialogFooter>
          {busy && <span className="me-auto text-xs text-muted-foreground">{t("vpn.nodes.loading")}</span>}
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.close")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ConnectionDialog({
  open,
  nodes,
  selection,
  connected,
  busy,
  loading,
  measuring,
  language,
  t,
  onOpenChange,
  onSelectNode,
  onChangeTypes,
  onToggleDelaySort,
  onMeasure,
  onReload,
}: {
  open: boolean;
  nodes: WhiteVPNNode[];
  selection: ConnectionSelection;
  connected: boolean;
  busy: boolean;
  loading: boolean;
  measuring: boolean;
  language: Language;
  t: TranslateFn;
  onOpenChange: (open: boolean) => void;
  onSelectNode: (name: string) => void;
  onChangeTypes: (types: string[]) => void;
  onToggleDelaySort: (delaySort: boolean) => void;
  onMeasure: (names: string[]) => void;
  onReload: () => void;
}) {
  const [search, setSearch] = useState("");
  const unknown = t("vpn.nodes.unknownCountry");

  const availableTypes = useMemo(() => {
    const seen = new Set<string>();
    for (const node of nodes) {
      if (node.type) {
        seen.add(node.type);
      }
    }
    return [...seen].sort();
  }, [nodes]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = nodes.filter((node) => {
      if (selection.types.length && !selection.types.includes(node.type)) {
        return false;
      }
      if (!needle) {
        return true;
      }
      return (
        node.label.toLowerCase().includes(needle) ||
        node.type.includes(needle) ||
        node.countryCode.toLowerCase().includes(needle) ||
        countryName(node.countryCode, language, unknown).toLowerCase().includes(needle)
      );
    });
    if (!selection.delaySort) {
      return filtered;
    }
    // Nodes without a measurement sink to the bottom rather than sorting as if
    // they answered instantly.
    return [...filtered].sort((a, b) => {
      const left = a.delayOk ? a.delayMs : Number.MAX_SAFE_INTEGER;
      const right = b.delayOk ? b.delayMs : Number.MAX_SAFE_INTEGER;
      return left - right;
    });
  }, [nodes, selection.types, selection.delaySort, search, language, unknown]);

  function toggleType(type: string) {
    const next = selection.types.includes(type)
      ? selection.types.filter((value: string) => value !== type)
      : [...selection.types, type];
    onChangeTypes(next);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100svh-4rem)] grid-rows-[auto_auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{t("vpn.connection.title")}</DialogTitle>
          <DialogDescription>{t("vpn.connection.description")}</DialogDescription>
        </DialogHeader>

        <div className="grid gap-3">
          <div className="relative">
            <Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={t("vpn.search")}
              className="ps-8"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">{t("vpn.types")}</span>
            <Button
              type="button"
              size="sm"
              variant={selection.types.length ? "outline" : "secondary"}
              className="h-7 px-2.5 text-xs"
              onClick={() => onChangeTypes([])}
            >
              {t("vpn.types.all")}
            </Button>
            {availableTypes.map((type) => (
              <Button
                key={type}
                type="button"
                size="sm"
                variant={selection.types.includes(type) ? "secondary" : "outline"}
                className="h-7 px-2.5 text-xs"
                onClick={() => toggleType(type)}
              >
                {type}
              </Button>
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={selection.delaySort} onCheckedChange={onToggleDelaySort} />
              {t("vpn.delaySort")}
            </label>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 px-2.5 text-xs"
                disabled={loading}
                onClick={onReload}
              >
                <RotateCcw className={cn("size-3.5", loading && "animate-spin")} />
                {t("vpn.nodes.reload")}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 px-2.5 text-xs"
                disabled={!connected || measuring}
                title={connected ? undefined : t("vpn.measure.needsConnection")}
                onClick={() => onMeasure(visible.map((node) => node.name))}
              >
                <Gauge className={cn("size-3.5", measuring && "animate-pulse")} />
                {measuring ? t("vpn.measuring") : t("vpn.measure")}
              </Button>
            </div>
          </div>
          {!connected && <p className="text-xs text-muted-foreground">{t("vpn.measure.needsConnection")}</p>}
        </div>

        <ScrollArea className="min-h-0">
          <div className="grid gap-1.5 pe-3">
            <SelectableRow selected={!selection.node} onClick={() => onSelectNode("")}>
              <span className="text-sm font-medium">{t("vpn.automatic")}</span>
              <span className="text-xs text-muted-foreground">
                {visible.length} {t("vpn.nodes.count")}
              </span>
            </SelectableRow>
            {visible.map((node) => (
              <SelectableRow key={node.name} selected={selection.node === node.name} onClick={() => onSelectNode(node.name)}>
                <span className="text-base leading-none">{flagFromCountryCode(node.countryCode) || "🏳️"}</span>
                <span className="min-w-0 flex-1 truncate text-sm" title={node.name}>
                  {node.label}
                </span>
                <Badge variant="outline" className="h-5 shrink-0 px-1.5 text-[10px] uppercase">
                  {node.type}
                </Badge>
                {node.delayOk && <span className="shrink-0 font-mono text-xs text-muted-foreground">{node.delayMs} ms</span>}
              </SelectableRow>
            ))}
            {!visible.length && (
              <p className="px-1 py-6 text-center text-sm text-muted-foreground">
                {loading ? t("vpn.nodes.loading") : t("vpn.nodes.none")}
              </p>
            )}
          </div>
          <ScrollBar orientation="vertical" />
        </ScrollArea>

        <DialogFooter>
          {busy && <span className="me-auto text-xs text-muted-foreground">{t("vpn.nodes.loading")}</span>}
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {t("common.close")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function connectButtonLabelKey(connectState: ConnectButtonState): StringKey {
  switch (connectState) {
    case "connecting":
      return "connect.connecting";
    case "disconnect":
      return "connect.disconnect";
    case "disconnecting":
      return "connect.disconnecting";
    case "retry":
      return "connect.retry";
    default:
      return "connect.connect";
  }
}

function ConnectButtonIcon({ state }: { state: ConnectButtonState }) {
  if (state === "connecting" || state === "disconnecting") {
    return <RotateCcw className="size-5 animate-spin" />;
  }
  if (state === "retry") {
    return <RotateCcw className="size-5" />;
  }
  if (state === "disconnect") {
    return <Square className="size-5" />;
  }
  return <Play className="size-5" />;
}

function WhiteDNSVPNPage({
  state,
  onState,
  onError,
  onNavigate,
  language,
  t,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onNavigate: (page: Page) => void;
  language: Language;
  t: TranslateFn;
}) {
  const runtime = state.runtime;
  const selectedSettings = effectiveV2RaySettingsProfile(state);
  const active = whiteDNSVPNRuntimeActive(state);
  const runtimeBusy = runtime.status !== "disconnected" && runtime.status !== "failed";
  const [pending, setPending] = useState<PendingAction>(null);
  const [nodes, setNodes] = useState<WhiteVPNNode[]>([]);
  const [nodesLoading, setNodesLoading] = useState(false);
  const [nodeDialog, setNodeDialog] = useState<"location" | "connection" | null>(null);
  const [selectionSaving, setSelectionSaving] = useState(false);
  const [measuring, setMeasuring] = useState(false);
  const selection = state.whiteVpn.connection;
  // A node is stored by name; the shorter label the row shows comes from the
  // catalogue, so a picked node means the catalogue is worth having loaded. It
  // is cached behind this call, so after the first time it costs nothing.
  useEffect(() => {
    if (selection.node && !nodes.length && !nodesLoading) {
      void loadNodes(false);
    }
  }, [selection.node]);
  const selectedNodeLabel = useMemo(() => {
    if (!selection.node) {
      return t("vpn.automatic");
    }
    return nodes.find((node) => node.name === selection.node)?.label || selection.node;
  }, [selection.node, nodes, t]);
  // Another runtime holding the machine is not this page's connection, so its
  // status must not drive this page's button.
  const otherRuntimeActive = runtimeBusy && !active;
  const connectState = otherRuntimeActive ? "connect" : connectButtonState(runtime.status, pending);
  const startsConnection = connectState === "connect" || connectState === "retry";
  const setupStatus = otherRuntimeActive ? "connecting" : connectCardStatus(connectState);
  const setupStatusLabel = otherRuntimeActive ? t("connect.busy") : translatedStatusLabel(t, setupStatus);
  const localProxyEndpoint = runtimeProxyDisplayEndpoint(runtime) || (selectedSettings ? proxyEndpoint(selectedSettings.listenIp, selectedSettings.listenPort) : "-");
  const selectedSettingsMissing = !selectedSettings || !selectedSettings.listenIp.trim() || selectedSettings.listenPort <= 0;
  // Disabled only while stopping, as on the phone: every other state has
  // something for a click to do, including connecting, which it stops.
  const connectDisabled =
    connectState === "disconnecting" ||
    otherRuntimeActive ||
    (startsConnection && (selectedSettingsMissing || pending !== null));
  const connectedFrontingIP = active ? runtime.frontingIp : "";
  const dashboardTitle = otherRuntimeActive
    ? t("vpn.card.otherRuntime")
    : connectState === "connecting"
      ? t("vpn.card.connecting")
      : connectState === "disconnecting"
        ? t("vpn.card.disconnecting")
        : connectState === "disconnect"
          ? t("vpn.card.connected")
          : connectState === "retry"
            ? t("vpn.card.failed")
            : t("vpn.card.ready");
  const dashboardDescription = otherRuntimeActive
    ? t("vpn.card.otherRuntime.description")
    : connectState === "connecting"
      ? runtime.status === "connecting" && runtime.progress.phase
        ? progressLabel(runtime.progress.phase, runtime.progress.percent)
        : t("vpn.card.connecting.description")
      : connectState === "disconnecting"
        ? t("vpn.card.disconnecting.description")
        : connectState === "disconnect"
          ? t("vpn.card.connected.description", { endpoint: localProxyEndpoint })
          : connectState === "retry"
            ? // The engine's own words when it has any: they say more about why
              // than any sentence written in advance can.
              runtime.message || t("vpn.card.failed.description")
            : t("vpn.card.ready.description");
  // Where traffic leaves from. The node's name carries a claim, and the app
  // measures the truth through the connection itself; the claim is shown at once
  // so the badge is not empty for the second the measurement takes, and is
  // replaced the moment there is something better than a claim.
  const exitCountry = useMemo(() => {
    if (connectState !== "disconnect") {
      return null;
    }
    const measured = Boolean(runtime.exitCountryCode);
    const code = runtime.exitCountryCode || runtime.nodeCountryCode;
    if (!code) {
      return null;
    }
    const claimed = runtime.nodeCountryCode;
    const title = measured
      ? [
          runtime.exitIp ? `${t("vpn.exit.ip")}: ${runtime.exitIp}` : "",
          claimed && claimed !== code ? t("vpn.exit.mismatch") : t("vpn.exit.measured"),
        ]
          .filter(Boolean)
          .join(" — ")
      : runtime.exitChecked
        ? t("vpn.exit.unmeasured")
        : t("vpn.exit.claimed");
    return {
      code,
      name: countryName(code, language, t("vpn.nodes.unknownCountry")),
      measured,
      // Spinning stops when the attempt does, whether or not it found anything.
      pending: !measured && !runtime.exitChecked,
      title,
    };
  }, [
    connectState,
    runtime.exitCountryCode,
    runtime.exitChecked,
    runtime.nodeCountryCode,
    runtime.exitIp,
    language,
    t,
  ]);

  const statusMetrics = [
    { label: t("vpn.metric.localProxy"), value: localProxyEndpoint, icon: Monitor },
    ...(exitCountry?.measured && runtime.exitIp
      ? [{ label: t("vpn.exit.ip"), value: `${flagFromCountryCode(exitCountry.code)} ${runtime.exitIp}`, icon: Globe }]
      : []),
    ...(connectedFrontingIP ? [{ label: t("vpn.metric.frontingIp"), value: connectedFrontingIP, icon: Shield }] : []),
    { label: t("vpn.metric.download"), value: formatSpeed(runtime.stats.downloadSpeedBytesPerSecond), icon: Download },
    { label: t("vpn.metric.upload"), value: formatSpeed(runtime.stats.uploadSpeedBytesPerSecond), icon: Upload },
  ];

  // One button, so one handler: what a click means is whatever the button
  // currently says.
  async function toggleConnection() {
    if (connectDisabled) {
      return;
    }
    if (startsConnection) {
      await startWhiteDNSVPN();
      return;
    }
    await stopRuntime();
  }

  async function startWhiteDNSVPN() {
    onError("");
    setPending("start");
    try {
      onState(await backend.startWhiteDNSVPNConnection());
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setPending(null);
    }
  }

  async function stopRuntime() {
    onError("");
    setPending("stop");
    try {
      onState(await backend.stopConnection());
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setPending(null);
    }
  }

  // The catalogue is loaded when a dialog first needs it, not on every visit to
  // the page: it is a network fetch, and most visits are to press Connect.
  async function loadNodes(refresh: boolean) {
    setNodesLoading(true);
    try {
      const list = await backend.listWhiteVpnNodes(refresh);
      setNodes(list.nodes || []);
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setNodesLoading(false);
    }
  }

  function openNodeDialog(dialog: "location" | "connection") {
    setNodeDialog(dialog);
    if (!nodes.length && !nodesLoading) {
      void loadNodes(false);
    }
  }

  // Every change to the four dashboard choices goes through here, so the one
  // that has to reach a running connection cannot be forgotten by one caller.
  async function saveSelection(countryCode: string, next: ConnectionSelection) {
    setSelectionSaving(true);
    onError("");
    try {
      onState(await backend.saveWhiteVpnSelection(countryCode, next));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSelectionSaving(false);
    }
  }

  async function measureDelays(names: string[]) {
    if (!names.length) {
      return;
    }
    setMeasuring(true);
    onError("");
    try {
      const list = await backend.measureWhiteVpnNodeDelays(names);
      setNodes(list.nodes || []);
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setMeasuring(false);
    }
  }

  async function refreshWhiteDNSVPN() {
    if (connectState !== "disconnect" || pending !== null) {
      return;
    }
    onError("");
    setPending("start");
    try {
      onState(await backend.refreshWhiteDNSVPNConnection());
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setPending(null);
    }
  }






  return (
    <PageShell eyebrow="WhiteVPN" title={t("nav.vpn")}>
      <div className="grid gap-3">
        <Card className={cn("relative overflow-hidden transition-all duration-500", statusCardTone(setupStatus))}>
          {setupStatus === "connected" && (
            <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/5 via-emerald-500/10 to-emerald-500/5 animate-pulse-slow" />
          )}
          <CardContent className="relative z-10 flex flex-col gap-5 p-6">
            <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div className="flex min-w-0 items-start gap-4">
                <div
                  className={cn(
                    "flex h-14 w-14 shrink-0 items-center justify-center rounded-full transition-all duration-300",
                    setupStatus === "connected" && "ring-4 ring-emerald-500/20 shadow-[0_0_20px_rgba(16,185,129,0.3)]"
                  )}
                >
                  <StatusDot status={setupStatus} className="size-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="mb-3 flex min-w-0 flex-wrap items-center gap-2">
                    <Badge variant={statusBadgeVariant(setupStatus)} className="h-6 px-3 font-medium">
                      {setupStatusLabel}
                    </Badge>
                    {exitCountry && (
                      <Badge variant="outline" className="h-6 gap-1.5 px-3" title={exitCountry.title}>
                        <span className="text-sm leading-none">{flagFromCountryCode(exitCountry.code)}</span>
                        <span className="font-medium">{exitCountry.code}</span>
                        <span className="max-w-40 truncate text-muted-foreground">{exitCountry.name}</span>
                        {exitCountry.pending && <RotateCcw className="size-3 animate-spin text-muted-foreground" />}
                      </Badge>
                    )}
                    <Badge variant="outline" className="h-6 gap-1 px-3">
                      <Monitor className="size-3" />
                      <span className="max-w-48 truncate font-mono">{localProxyEndpoint}</span>
                    </Badge>
                    <Badge variant="outline" className="h-6 gap-1 px-3">
                      <Shield className="size-3" />
                      <span className="font-mono">{connectedFrontingIP || t("vpn.frontingAuto")}</span>
                    </Badge>
                  </div>
                  <h2 className="text-2xl font-bold tracking-tight">{dashboardTitle}</h2>
                  <p className="mt-2 text-sm text-muted-foreground">{dashboardDescription}</p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:justify-end">
                {connectState === "disconnect" && (
                  <Button
                    type="button"
                    variant="outline"
                    size="lg"
                    className="h-11 min-w-36 px-6 font-semibold"
                    disabled={pending !== null}
                    onClick={refreshWhiteDNSVPN}
                  >
                    <RotateCcw className="size-5" />
                    {t("connect.refresh")}
                  </Button>
                )}
                <Button
                  type="button"
                  variant={startsConnection ? "default" : "outline"}
                  size="lg"
                  className={cn(
                    "h-11 min-w-36 px-6 font-semibold",
                    startsConnection && !connectDisabled && "bg-emerald-600 hover:bg-emerald-700"
                  )}
                  disabled={connectDisabled}
                  // While connecting the label is a state and the click is an
                  // action, so the accessible name has to be the action.
                  title={connectState === "connecting" ? t("connect.cancelHint") : undefined}
                  aria-label={connectState === "connecting" ? t("connect.cancelHint") : undefined}
                  onClick={toggleConnection}
                >
                  <ConnectButtonIcon state={connectState} />
                  {t(connectButtonLabelKey(connectState))}
                </Button>
              </div>
            </div>

            <div className="rounded-lg border-2 bg-card p-4">
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                {statusMetrics.map((metric) => {
                  const Icon = metric.icon;
                  return (
                    <div key={metric.label} className="flex min-w-0 items-center gap-3 rounded-md border bg-background/70 px-3 py-2">
                      <Icon className="size-3.5 shrink-0 text-muted-foreground" />
                      <div className="min-w-0">
                        <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{metric.label}</p>
                        <p className="truncate text-sm font-semibold">{metric.value}</p>
                      </div>
                    </div>
                  );
                })}
                {setupStatus === "connected" && runtime.trafficMonitorMessage && (
                  <div className="flex min-w-0 items-center gap-3 rounded-md border bg-background/70 px-3 py-2">
                    <Gauge className="size-3.5 shrink-0 text-muted-foreground" />
                    <div className="min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t("vpn.metric.traffic")}</p>
                      <p className="truncate text-sm font-semibold">{runtime.trafficMonitorMessage}</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="p-3 pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Globe className="size-4" />
              {t("vpn.rows.title")}
            </CardTitle>
            <CardDescription className="text-xs">{t("vpn.rows.description")}</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2 p-3 pt-0">
            <DashboardRow
              icon={<Globe className="size-4" />}
              label={t("vpn.location")}
              value={
                state.whiteVpn.countryCode
                  ? `${flagFromCountryCode(state.whiteVpn.countryCode)} ${countryName(state.whiteVpn.countryCode, language, t("vpn.nodes.unknownCountry"))}`
                  : t("vpn.automatic")
              }
              disabled={selectionSaving}
              onClick={() => openNodeDialog("location")}
            />
            <DashboardRow
              icon={<Wifi className="size-4" />}
              label={t("vpn.connection")}
              value={selectedNodeLabel}
              disabled={selectionSaving}
              onClick={() => openNodeDialog("connection")}
            />

            {/* The tunnel, DNS privacy and split tunnel used to sit here and
                wrote to the V2Ray settings profile, which only the Xray path
                reads. Under the engine this app now runs they changed nothing.
                One place to change a setting is worth more than two. */}
            <p className="pt-1 text-xs text-muted-foreground">{t("vpn.moreSettings")}</p>
            <Button variant="outline" size="sm" className="justify-self-start" onClick={() => onNavigate("settings")}>
              <Settings className="size-3.5" />
              {t("settings.title")}
            </Button>
          </CardContent>
        </Card>

      </div>

      <LocationDialog
        open={nodeDialog === "location"}
        nodes={nodes}
        selected={state.whiteVpn.countryCode}
        busy={selectionSaving}
        loading={nodesLoading}
        language={language}
        t={t}
        onOpenChange={(open) => !open && setNodeDialog(null)}
        onSelect={(countryCode) => {
          // Choosing a country abandons a node picked by hand: the two can
          // contradict each other, and the row the user just touched wins.
          void saveSelection(countryCode, { ...selection, node: "" });
          setNodeDialog(null);
        }}
      />

      <ConnectionDialog
        open={nodeDialog === "connection"}
        nodes={nodes}
        selection={selection}
        connected={connectState === "disconnect"}
        busy={selectionSaving}
        loading={nodesLoading}
        measuring={measuring}
        language={language}
        t={t}
        onOpenChange={(open) => !open && setNodeDialog(null)}
        onSelectNode={(name) => {
          void saveSelection(state.whiteVpn.countryCode, { ...selection, node: name });
          setNodeDialog(null);
        }}
        onChangeTypes={(types) => void saveSelection(state.whiteVpn.countryCode, { ...selection, types, node: "" })}
        onToggleDelaySort={(delaySort) => void saveSelection(state.whiteVpn.countryCode, { ...selection, delaySort })}
        onMeasure={(names) => void measureDelays(names)}
        onReload={() => void loadNodes(true)}
      />

      {selectedSettingsMissing && (
        <Alert className="border-amber-200 bg-amber-50 text-amber-950">
          <AlertCircle />
          <AlertTitle>{t("vpn.alert.settingsRequired")}</AlertTitle>
          <AlertDescription>{t("vpn.alert.settingsRequired.description")}</AlertDescription>
        </Alert>
      )}
      {otherRuntimeActive && (
        <Alert>
          <AlertCircle />
          <AlertTitle>{t("vpn.card.otherRuntime")}</AlertTitle>
          <AlertDescription>{t("vpn.card.otherRuntime.description")}</AlertDescription>
        </Alert>
      )}
    </PageShell>
  );
}

// One measurement, in whichever of its four states it is: waiting to be run,
// running, run and failed, run and measured. Failure and "not run yet" were the
// same dash until a user reported nodes whose tests "did not happen" — they had
// happened, and had failed, which is the more useful of the two answers.
function MeasurementCell({
  tested,
  ok,
  pending,
  reason,
  children,
  quality,
  t,
}: {
  tested: boolean;
  ok: boolean;
  pending: boolean;
  reason?: string;
  children: ReactNode;
  quality?: "good" | "fair" | "poor";
  t: TranslateFn;
}) {
  if (pending) {
    return (
      <span className="inline-flex items-center gap-1 text-muted-foreground">
        <RotateCcw className="size-3 animate-spin" />
      </span>
    );
  }
  if (!tested) {
    return <span className="text-muted-foreground">-</span>;
  }
  if (!ok) {
    return (
      <span className="cursor-help text-destructive underline decoration-dotted underline-offset-2" title={reason || t("servers.failed.hint")}>
        {t("servers.failed")}
      </span>
    );
  }
  return (
    <span
      className={cn(
        quality === "good" && "text-emerald-600 dark:text-emerald-400",
        quality === "fair" && "text-amber-600 dark:text-amber-400",
        quality === "poor" && "text-orange-600 dark:text-orange-400"
      )}
    >
      {children}
    </span>
  );
}

// Thresholds, so a column can be read at a glance rather than compared by hand.
function latencyQuality(ms: number): "good" | "fair" | "poor" {
  if (ms <= 300) {
    return "good";
  }
  return ms <= 800 ? "fair" : "poor";
}

function speedQuality(bytesPerSecond: number): "good" | "fair" | "poor" {
  if (bytesPerSecond >= 2 * 1024 * 1024) {
    return "good";
  }
  return bytesPerSecond >= 512 * 1024 ? "fair" : "poor";
}

// The Servers page: the workbench.
//
// It and the dashboard's connection dialog read the same list — the one the
// engine itself is built from — so they cannot disagree about how many nodes
// there are or what protocols they speak. That was the whole problem with the
// page this replaces: it read a second parser's output, which accepted
// protocols the engine cannot carry and stopped refreshing entirely once the
// path that filled it was removed.
//
// The dialog is for picking one quickly. This is for finding out which one to
// pick: test, sort, compare, share.
type NodeSortColumn = "label" | "country" | "type" | "reach" | "delay" | "speed";
type NodeSort = { column: NodeSortColumn; direction: "asc" | "desc" };

// Mirrors session.DefaultSpeedURL. Ten megabytes: enough that a fast node is
// not measuring its own start-up, small enough that a slow one is not still
// going when the budget runs out.
const defaultSpeedTestURL = "https://speed.cloudflare.com/__down?bytes=10000000";

const defaultNodeTest: NodeTestRequest = {
  nodes: [],
  reachability: true,
  delay: false,
  speed: false,
  reachabilityTimeoutMs: 3500,
  reachabilityWorkers: 64,
  delayTimeoutMs: 5000,
  delayWorkers: 16,
  delayUrl: "",
  speedBudgetMs: 8000,
  speedUrl: defaultSpeedTestURL,
};

function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

function NodesPage({
  state,
  nodes,
  loading,
  testing,
  onReload,
  onRunTest,
  onCancelTest,
  onSelectNode,
  onError,
  onSuccess,
  language,
  t,
}: {
  state: AppState;
  nodes: WhiteVPNNode[];
  loading: boolean;
  testing: boolean;
  onReload: () => void;
  onRunTest: (request: NodeTestRequest) => void;
  onCancelTest: () => void;
  onSelectNode: (name: string) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  language: Language;
  t: TranslateFn;
}) {
  const [search, setSearch] = useState("");
  const [country, setCountry] = useState("");
  const [protocol, setProtocol] = useState("");
  const [sort, setSort] = useState<NodeSort>({ column: "label", direction: "asc" });
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [request, setRequest] = useState<NodeTestRequest>(defaultNodeTest);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [shareNode, setShareNode] = useState<WhiteVPNNode | null>(null);
  const unknown = t("vpn.nodes.unknownCountry");

  const countries = useMemo(() => countryOptions(nodes, language, unknown), [nodes, language, unknown]);
  const protocols = useMemo(() => [...new Set(nodes.map((node) => node.type).filter(Boolean))].sort(), [nodes]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = nodes.filter((node) => {
      if (country && node.countryCode !== country) {
        return false;
      }
      if (protocol && node.type !== protocol) {
        return false;
      }
      if (!needle) {
        return true;
      }
      return (
        node.label.toLowerCase().includes(needle) ||
        node.server.toLowerCase().includes(needle) ||
        node.type.includes(needle) ||
        countryName(node.countryCode, language, unknown).toLowerCase().includes(needle)
      );
    });

    // Unmeasured sinks to the bottom whichever way the column is sorted: it is
    // absence, not a value, and it should never sit above a real measurement.
    const rank = (node: WhiteVPNNode): number | string => {
      switch (sort.column) {
        case "country":
          return countryName(node.countryCode, language, unknown);
        case "type":
          return node.type;
        case "reach":
          return node.reachOk ? node.reachMs : Number.MAX_SAFE_INTEGER;
        case "delay":
          return node.delayOk ? node.delayMs : Number.MAX_SAFE_INTEGER;
        case "speed":
          return node.speedOk ? -node.speedBytesPerSecond : Number.MAX_SAFE_INTEGER;
        default:
          return node.label;
      }
    };
    const sorted = [...filtered].sort((a, b) => {
      const left = rank(a);
      const right = rank(b);
      if (typeof left === "string" || typeof right === "string") {
        return String(left).localeCompare(String(right), language);
      }
      return left - right;
    });
    return sort.direction === "desc" ? sorted.reverse() : sorted;
  }, [nodes, search, country, protocol, sort, language, unknown]);

  const selectedNames = useMemo(() => visible.filter((node) => selected.has(node.name)).map((node) => node.name), [visible, selected]);
  const targets = selectedNames.length ? selectedNames : visible.map((node) => node.name);

  function toggleSort(column: NodeSortColumn) {
    setSort((current) =>
      current.column === column
        ? { column, direction: current.direction === "asc" ? "desc" : "asc" }
        : { column, direction: column === "speed" ? "asc" : "asc" }
    );
  }

  function toggleSelected(name: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }

  // A row has to show that its turn has not come yet, or a long run looks like
  // a broken one. The backend reports each result as it lands; anything in the
  // run that has not reported is still waiting.
  const [pending, setPending] = useState<{ nodes: Set<string>; tests: NodeTestRequest } | null>(null);
  useEffect(() => {
    if (!testing) {
      setPending(null);
    }
  }, [testing]);

  function pendingFor(name: string, test: "reachability" | "delay" | "speed"): boolean {
    if (!pending || !pending.nodes.has(name) || !pending.tests[test]) {
      return false;
    }
    const node = nodes.find((entry) => entry.name === name);
    if (!node) {
      return false;
    }
    // A result for this test clears it; results for the others do not.
    return test === "reachability" ? !node.reachTested : test === "delay" ? !node.delayTested : !node.speedTested;
  }

  function runTests() {
    if (!targets.length) {
      onError(t("vpn.nodes.none"));
      return;
    }
    setPending({ nodes: new Set(targets), tests: request });
    onRunTest({ ...request, nodes: targets });
  }

  async function copyLink(node: WhiteVPNNode) {
    try {
      await navigator.clipboard?.writeText(node.link);
      onSuccess(t("servers.copied"));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  const subscriptionName =
    state.v2raySubscriptions.find((subscription) => subscription.id === state.selectedSubscriptionId)?.name || "";

  return (
    <PageShell
      eyebrow="WhiteVPN"
      title={t("nav.servers")}
      actions={
        <>
          <Button variant="outline" onClick={onReload} disabled={loading}>
            <RotateCcw className={cn(loading && "animate-spin")} />
            {t("vpn.nodes.reload")}
          </Button>
          {testing ? (
            <Button variant="destructive" onClick={onCancelTest}>
              <Square />
              {t("servers.stop")}
            </Button>
          ) : (
            <Button onClick={runTests} disabled={!visible.length}>
              <Gauge />
              {selectedNames.length ? t("servers.testSelected") : t("servers.testAll")}
            </Button>
          )}
        </>
      }
    >
      <Card>
        <CardHeader className="p-3 pb-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            <Shield className="size-4" />
            {subscriptionName || t("nav.subscriptions")}
            <Badge variant="outline">
              {visible.length} / {nodes.length} {t("vpn.nodes.count")}
            </Badge>
            {selectedNames.length > 0 && <Badge>{selectedNames.length} {t("servers.selected")}</Badge>}
          </CardTitle>
          <CardDescription className="text-xs">{t("servers.description")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 p-3 pt-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-48 flex-1">
              <Search className="pointer-events-none absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("vpn.search")} className="ps-8" />
            </div>
            <Select value={country || "all"} onValueChange={(value) => setCountry(value === "all" ? "" : value)}>
              <SelectTrigger className="w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="all">{t("vpn.location")}: {t("vpn.types.all")}</SelectItem>
                {countries.map((entry) => (
                  <SelectItem key={entry.code} value={entry.code}>
                    {flagFromCountryCode(entry.code)} {entry.name} ({entry.count})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={protocol || "all"} onValueChange={(value) => setProtocol(value === "all" ? "" : value)}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="all">{t("vpn.types")}: {t("vpn.types.all")}</SelectItem>
                {protocols.map((type) => (
                  <SelectItem key={type} value={type}>
                    {type}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-wrap items-center gap-3 rounded-md border bg-background/60 px-3 py-2">
            <span className="text-xs font-medium text-muted-foreground">{t("servers.tests")}</span>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={request.reachability} onCheckedChange={(checked) => setRequest({ ...request, reachability: checked })} />
              {t("servers.test.reach")}
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={request.delay} onCheckedChange={(checked) => setRequest({ ...request, delay: checked })} />
              {t("servers.test.delay")}
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={request.speed} onCheckedChange={(checked) => setRequest({ ...request, speed: checked })} />
              {t("servers.test.speed")}
            </label>
            <Button variant="ghost" size="sm" className="ms-auto" onClick={() => setOptionsOpen((open) => !open)}>
              <SlidersHorizontal className="size-3.5" />
              {t("servers.testOptions")}
            </Button>
          </div>

          {optionsOpen && (
            <FieldGroup className="grid gap-3 rounded-md border bg-background/60 p-3 md:grid-cols-3">
              <NumberField
                label={t("servers.option.reachTimeout")}
                value={request.reachabilityTimeoutMs}
                min={500}
                max={60000}
                onChange={(value) => setRequest({ ...request, reachabilityTimeoutMs: value })}
              />
              <NumberField
                label={t("servers.option.reachWorkers")}
                value={request.reachabilityWorkers}
                min={1}
                max={256}
                onChange={(value) => setRequest({ ...request, reachabilityWorkers: value })}
              />
              <NumberField
                label={t("servers.option.delayTimeout")}
                value={request.delayTimeoutMs}
                min={500}
                max={60000}
                onChange={(value) => setRequest({ ...request, delayTimeoutMs: value })}
              />
              <NumberField
                label={t("servers.option.delayWorkers")}
                value={request.delayWorkers}
                min={1}
                max={256}
                onChange={(value) => setRequest({ ...request, delayWorkers: value })}
              />
              <NumberField
                label={t("servers.option.speedBudget")}
                value={request.speedBudgetMs}
                min={500}
                max={60000}
                onChange={(value) => setRequest({ ...request, speedBudgetMs: value })}
              />
              <TextField
                label={t("servers.option.speedUrl")}
                value={request.speedUrl}
                placeholder="https://speed.cloudflare.com/__down?bytes=10000000"
                onChange={(value) => setRequest({ ...request, speedUrl: value })}
              />
              <FieldDescription className="md:col-span-3">{t("servers.option.hint")}</FieldDescription>
            </FieldGroup>
          )}
        </CardContent>
      </Card>

      <Card className="min-h-0">
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100svh-24rem)]">
            <table className="w-full min-w-[860px] table-fixed text-start text-sm">
              <thead className="sticky top-0 z-10 bg-muted/95 text-xs uppercase text-muted-foreground backdrop-blur">
                <tr>
                  <th className="w-10 px-2 py-2"></th>
                  <NodeHeader column="country" sort={sort} onSort={toggleSort} className="w-32">
                    {t("vpn.location")}
                  </NodeHeader>
                  <NodeHeader column="label" sort={sort} onSort={toggleSort}>
                    {t("servers.column.node")}
                  </NodeHeader>
                  <NodeHeader column="type" sort={sort} onSort={toggleSort} className="w-24">
                    {t("vpn.types")}
                  </NodeHeader>
                  <th className="w-44 px-2 py-2 font-medium">{t("servers.column.address")}</th>
                  <NodeHeader column="reach" sort={sort} onSort={toggleSort} className="w-24 text-end">
                    {t("servers.test.reach")}
                  </NodeHeader>
                  <NodeHeader column="delay" sort={sort} onSort={toggleSort} className="w-24 text-end">
                    {t("servers.test.delay")}
                  </NodeHeader>
                  <NodeHeader column="speed" sort={sort} onSort={toggleSort} className="w-28 text-end">
                    {t("servers.test.speed")}
                  </NodeHeader>
                  <th className="w-24 px-2 py-2 text-end font-medium">{t("servers.column.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((node) => (
                  <tr key={node.name} className="border-b last:border-b-0 hover:bg-muted/40">
                    <td className="px-2 py-1.5">
                      <input
                        type="checkbox"
                        className="size-4"
                        checked={selected.has(node.name)}
                        onChange={() => toggleSelected(node.name)}
                        aria-label={node.label}
                      />
                    </td>
                    <td className="min-w-0 px-2 py-1.5">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className="leading-none">{flagFromCountryCode(node.countryCode) || "🏳️"}</span>
                        <span className="truncate text-xs">{countryName(node.countryCode, language, unknown)}</span>
                      </span>
                    </td>
                    <td className="min-w-0 px-2 py-1.5">
                      <span className="block truncate" title={node.name}>
                        {node.label}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <Badge variant="outline" className="h-5 px-1.5 text-[10px] uppercase">
                        {node.type}
                      </Badge>
                    </td>
                    <td className="min-w-0 px-2 py-1.5">
                      <span className="block truncate font-mono text-xs text-muted-foreground">
                        {node.server}:{node.port}
                      </span>
                    </td>
                    <td className="px-2 py-1.5 text-end font-mono text-xs">
                      <MeasurementCell
                        tested={node.reachTested}
                        ok={node.reachOk}
                        pending={pendingFor(node.name, "reachability")}
                        reason={node.reachError}
                        quality={latencyQuality(node.reachMs)}
                        t={t}
                      >
                        {node.reachMs} ms
                      </MeasurementCell>
                    </td>
                    <td className="px-2 py-1.5 text-end font-mono text-xs">
                      <MeasurementCell
                        tested={node.delayTested}
                        ok={node.delayOk}
                        pending={pendingFor(node.name, "delay")}
                        reason={node.delayError}
                        quality={latencyQuality(node.delayMs)}
                        t={t}
                      >
                        {node.delayMs} ms
                      </MeasurementCell>
                    </td>
                    <td className="px-2 py-1.5 text-end font-mono text-xs">
                      <MeasurementCell
                        tested={node.speedTested}
                        ok={node.speedOk}
                        pending={pendingFor(node.name, "speed")}
                        reason={node.speedError}
                        quality={speedQuality(node.speedBytesPerSecond)}
                        t={t}
                      >
                        {formatRate(node.speedBytesPerSecond)}
                      </MeasurementCell>
                    </td>
                    <td className="px-2 py-1.5">
                      <div className="flex justify-end gap-1">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon-sm" onClick={() => onSelectNode(node.name)} aria-label={t("servers.use")}>
                              <Play />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{t("servers.use")}</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon-sm" onClick={() => setShareNode(node)} aria-label={t("servers.share")}>
                              <Share2 />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{t("servers.share")}</TooltipContent>
                        </Tooltip>
                      </div>
                    </td>
                  </tr>
                ))}
                {!visible.length && (
                  <tr>
                    <td colSpan={9} className="px-3 py-10 text-center text-sm text-muted-foreground">
                      {loading ? t("vpn.nodes.loading") : t("vpn.nodes.none")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <ScrollBar orientation="vertical" />
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={Boolean(shareNode)} onOpenChange={(open) => !open && setShareNode(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("servers.share")}</DialogTitle>
            <DialogDescription>{shareNode?.label}</DialogDescription>
          </DialogHeader>
          <Textarea
            readOnly
            value={shareNode?.link || ""}
            className="h-28 min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setShareNode(null)}>
              {t("common.close")}
            </Button>
            <Button onClick={() => shareNode && void copyLink(shareNode)}>
              <Copy />
              {t("servers.copy")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageShell>
  );
}

function NodeHeader({
  column,
  sort,
  onSort,
  className,
  children,
}: {
  column: NodeSortColumn;
  sort: NodeSort;
  onSort: (column: NodeSortColumn) => void;
  className?: string;
  children: ReactNode;
}) {
  const active = sort.column === column;
  return (
    <th className={cn("px-2 py-2 font-medium", className)}>
      <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => onSort(column)}>
        {children}
        {active && <ChevronDown className={cn("size-3", sort.direction === "asc" && "rotate-180")} />}
      </button>
    </th>
  );
}

function V2RaySubscriptionsPage({
  state,
  onState,
  onError,
  onSuccess,
  t,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  t: TranslateFn;
}) {
  const fallbackDraft = useMemo(() => defaultV2RaySubscriptionDraft(), []);
  const [draft, setDraft] = useState(fallbackDraft);
  const [editorOpen, setEditorOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<V2RaySubscription | null>(null);
  const [refreshingSubscriptionIds, setRefreshingSubscriptionIds] = useState<Record<string, boolean>>({});
  const [selectingSubscription, setSelectingSubscription] = useState(false);
  const profileIndex = useMemo(
    () => buildV2RayProfileIndex(state.v2rayProfiles, {}, {}),
    [state.v2rayProfiles]
  );
  const saveDisabled = !draft.url.trim();

  useEffect(() => {
    if (!editorOpen) {
      setDraft(fallbackDraft);
    }
  }, [editorOpen, fallbackDraft]);

  function openNewSubscription() {
    onError("");
    setDraft(defaultV2RaySubscriptionDraft());
    setEditorOpen(true);
  }

  function openExistingSubscription(subscription: V2RaySubscription) {
    onError("");
    setDraft(normalizeV2RaySubscription(subscription));
    setEditorOpen(true);
  }

  async function saveSubscription() {
    onError("");
    try {
      const nextState = await backend.saveV2RaySubscription(draft);
      onState(nextState);
      const saved =
        nextState.v2raySubscriptions.find((subscription) => subscription.id === draft.id) ||
        nextState.v2raySubscriptions[nextState.v2raySubscriptions.length - 1];
      if (saved) {
        setDraft(normalizeV2RaySubscription(saved));
      }
      setEditorOpen(false);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  // Which subscription the VPN connects through. Changing it clears a node
  // picked by hand, because that pick named a node in the old list.
  async function useSubscription(id: string) {
    if (selectingSubscription) {
      return;
    }
    onError("");
    setSelectingSubscription(true);
    try {
      onState(await backend.selectSubscription(id));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSelectingSubscription(false);
    }
  }

  async function refreshSubscription(subscription: V2RaySubscription) {
    if (!subscription.id || refreshingSubscriptionIds[subscription.id]) {
      return;
    }
    onError("");
    setRefreshingSubscriptionIds((current) => ({ ...current, [subscription.id]: true }));
    try {
      const result = await backend.refreshV2RaySubscription(subscription.id);
      onState(result.state);
      if (draft.id === subscription.id) {
        setDraft(normalizeV2RaySubscription(result.subscription));
      }
      if (result.ok) {
        onSuccess(result.message || `Imported ${result.imported} V2Ray profile${result.imported === 1 ? "" : "s"}.`);
      } else {
        onError(result.message || "Subscription refresh failed.");
      }
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setRefreshingSubscriptionIds((current) => {
        const next = { ...current };
        delete next[subscription.id];
        return next;
      });
    }
  }

  function requestDeleteSubscription(subscription: V2RaySubscription) {
    if (!subscription.id) {
      return;
    }
    onError("");
    setDeleteTarget(normalizeV2RaySubscription(subscription));
    setEditorOpen(false);
  }

  async function deleteSubscription(subscription: V2RaySubscription) {
    if (!subscription.id) {
      return;
    }
    onError("");
    try {
      const beforeManagedIds = profileIndex.subscriptionProfileIds[subscription.id] || [];
      const nextState = await backend.deleteV2RaySubscription(subscription.id);
      onState(nextState);
      setDeleteTarget(null);
      setEditorOpen(false);
      onSuccess(
        `Deleted V2Ray subscription and ${beforeManagedIds.length} related config${beforeManagedIds.length === 1 ? "" : "s"}.`
      );
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  const deleteTargetConfigCount = deleteTarget?.id ? (profileIndex.subscriptionProfileIds[deleteTarget.id]?.length || 0) : 0;

  return (
    <>
      <PageShell
        eyebrow="WhiteVPN"
        title="Subscriptions"
        actions={
          <Button type="button" variant="outline" onClick={openNewSubscription}>
            <Plus />
            New subscription
          </Button>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
            <div className="min-w-0">
              <p className="text-sm font-semibold">Subscription groups</p>
              <p className="text-xs text-muted-foreground">
                {state.v2raySubscriptions.length} source{state.v2raySubscriptions.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
          {state.v2raySubscriptions.length === 0 ? (
            <div className="px-3 py-4 text-sm text-muted-foreground">No saved subscription URLs.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[800px] table-fixed text-start">
                <colgroup>
                  <col className="w-[24%]" />
                  <col className="w-[34%]" />
                  <col className="w-[14%]" />
                  <col className="w-[18%]" />
                  <col className="w-[10%]" />
                </colgroup>
                <thead className="border-b bg-muted/20 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 font-medium">Name</th>
                    <th className="px-3 py-2 font-medium">URL</th>
                    <th className="px-3 py-2 font-medium">Profiles</th>
                    <th className="px-3 py-2 font-medium">Status</th>
                    <th className="px-3 py-2 text-end font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {state.v2raySubscriptions.map((subscription) => {
                    const refreshing = Boolean(refreshingSubscriptionIds[subscription.id]);
                    const managedProfileIds = profileIndex.subscriptionProfileIds[subscription.id] || [];
                    const builtIn = subscription.id === whiteDNSVPNSubscriptionID;
                    const inUse = subscription.id === state.selectedSubscriptionId;
                    // Said on the row rather than once when it was added: a
                    // server list fetched in the clear can be read and replaced
                    // by anyone on the path, and that stays true every day.
                    const inTheClear = subscription.url.toLowerCase().startsWith("http://");
                    // The built-in catalogue comes back on the next connect,
                    // so removing it is an offer the app cannot keep.
                    const deleteDisabled =
                      builtIn ||
                      (profileSelectionLocked(state.runtime) &&
                        v2RayRuntimeActive(state) &&
                        managedProfileIds.includes(state.runtime.activeConnectionId));
                    return (
                      <tr
                        key={subscription.id}
                        role="button"
                        tabIndex={0}
                        className="cursor-pointer border-b text-sm transition-colors last:border-b-0 hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
                        onClick={() => !builtIn && openExistingSubscription(subscription)}
                        onKeyDown={(event) => {
                          if (!builtIn && (event.key === "Enter" || event.key === " ")) {
                            event.preventDefault();
                            openExistingSubscription(subscription);
                          }
                        }}
                      >
                        <td className="min-w-0 px-3 py-3">
                          <span className="flex min-w-0 items-center gap-2">
                            <span className="truncate font-medium">{subscription.name || "V2Ray Subscription"}</span>
                            {inUse && (
                              <Badge variant="default" className="shrink-0">
                                {t("subs.inUse")}
                              </Badge>
                            )}
                          </span>
                        </td>
                        <td className="min-w-0 px-3 py-3">
                          {/* The built-in catalogue's address is the app's, not
                              the user's, and is not carried in the state at all
                              — there is nothing here to print. */}
                          <span className="flex min-w-0 items-center gap-1.5">
                            {inTheClear && (
                              <AlertCircle className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" aria-label={t("subs.inTheClear")} />
                            )}
                            <span className={cn("truncate text-xs", builtIn ? "text-muted-foreground" : "font-mono", inTheClear && "text-amber-600 dark:text-amber-400")} title={inTheClear ? t("subs.inTheClear") : undefined}>
                              {builtIn ? "Built-in" : subscription.url}
                            </span>
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          {/* The subscription's own count, which its refresh
                              updates. It used to show how many profiles were
                              stored for it, which stopped being the same number
                              the moment nothing stored them. */}
                          <Badge variant="secondary">{subscription.importedCount || managedProfileIds.length || 0}</Badge>
                        </td>
                        <td className="min-w-0 px-3 py-3">
                          <span className={cn("block truncate text-xs", subscription.lastError ? "text-destructive" : "text-muted-foreground")}>
                            {v2raySubscriptionStatusLabel(subscription)}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-end">
                          <div className="flex justify-end gap-1">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  disabled={inUse || selectingSubscription || profileSelectionLocked(state.runtime)}
                                  aria-label={`Use ${subscription.name || "V2Ray subscription"}`}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    void useSubscription(subscription.id);
                                  }}
                                  onKeyDown={(event) => event.stopPropagation()}
                                >
                                  <Check />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                {inUse
                                  ? t("subs.inUse")
                                  : profileSelectionLocked(state.runtime)
                                    ? t("subs.disconnectFirst")
                                    : t("subs.use")}
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  disabled={refreshing}
                                  aria-label={`Refresh ${subscription.name || "V2Ray subscription"}`}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    void refreshSubscription(subscription);
                                  }}
                                  onKeyDown={(event) => event.stopPropagation()}
                                >
                                  <RotateCcw className={cn(refreshing && "animate-spin")} />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>{refreshing ? "Refreshing" : "Refresh"}</TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-sm"
                                  disabled={deleteDisabled}
                                  aria-label={`Delete ${subscription.name || "V2Ray subscription"}`}
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    requestDeleteSubscription(subscription);
                                  }}
                                  onKeyDown={(event) => event.stopPropagation()}
                                >
                                  <Trash2 />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                {builtIn ? "The built-in catalogue stays" : deleteDisabled ? "Disconnect first" : "Delete subscription and related configs"}
                              </TooltipContent>
                            </Tooltip>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </PageShell>

      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] overflow-hidden sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{draft.id ? draft.name : "New subscription"}</DialogTitle>
            <DialogDescription>Saved V2Ray subscription URL</DialogDescription>
          </DialogHeader>
          <FieldGroup className="grid gap-4">
            <TextField label="Name" value={draft.name} onChange={(name) => setDraft({ ...draft, name })} />
            <TextField
              label="Subscription URL"
              value={draft.url}
              onChange={(url) => setDraft({ ...draft, url })}
              placeholder="https://example.com/sub"
            />
            {draft.lastError && (
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>Last refresh failed</AlertTitle>
                <AlertDescription>{draft.lastError}</AlertDescription>
              </Alert>
            )}
          </FieldGroup>
          <DialogFooter className="sm:justify-between">
            {draft.id ? (
              <Button type="button" variant="destructive" onClick={() => requestDeleteSubscription(draft)} className="sm:me-auto">
                <Trash2 />
                Delete
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button type="button" variant="outline" onClick={() => setEditorOpen(false)}>
                Cancel
              </Button>
              {draft.id && (
                <Button type="button" variant="outline" disabled={Boolean(refreshingSubscriptionIds[draft.id])} onClick={() => refreshSubscription(draft)}>
                  <RotateCcw className={cn(refreshingSubscriptionIds[draft.id] && "animate-spin")} />
                  Refresh
                </Button>
              )}
              <Button type="button" disabled={saveDisabled} onClick={saveSubscription}>
                <Save />
                Save
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Delete V2Ray subscription?</DialogTitle>
            <DialogDescription>
              This will delete {deleteTarget?.name || "this subscription"} and {deleteTargetConfigCount} related V2Ray config{deleteTargetConfigCount === 1 ? "" : "s"}. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={!deleteTarget}
              onClick={() => {
                if (deleteTarget) {
                  void deleteSubscription(deleteTarget);
                }
              }}
            >
              <Trash2 />
              Delete subscription and configs
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

type V2RayProfileIndex = {
  hasExportable: boolean;
  fastestProfile?: V2RayProfile;
  failedProfiles: V2RayProfile[];
  uncheckedProfiles: V2RayProfile[];
  profileById: Record<string, V2RayProfile>;
  subscriptionProfileIds: Record<string, string[]>;
  manualProfileCount: number;
};

function buildV2RayProfileIndex(
  profiles: V2RayProfile[],
  results: Record<string, V2RayPingResult>,
  scanningIds: Record<string, boolean>
): V2RayProfileIndex {
  const failedProfiles: V2RayProfile[] = [];
  const uncheckedProfiles: V2RayProfile[] = [];
  const profileById: Record<string, V2RayProfile> = {};
  const subscriptionProfileIds: Record<string, string[]> = {};
  let fastestProfile: V2RayProfile | undefined;
  let hasExportable = false;
  let manualProfileCount = 0;

  profiles.forEach((profile) => {
    profileById[profile.id] = profile;
    const result = results[profile.id];
    const scanning = Boolean(scanningIds[profile.id]);
    if (!hasExportable && isExportableV2RayProfile(profile)) {
      hasExportable = true;
    }
    if (result?.delayOk || (result?.ok && result.latencyMs > 0)) {
      const fastestResult = fastestProfile ? results[fastestProfile.id] : undefined;
      if (!fastestProfile || v2rayDelaySortValue(result) < v2rayDelaySortValue(fastestResult)) {
        fastestProfile = profile;
      }
    } else if (result && !result.speedOk) {
      failedProfiles.push(profile);
    } else if (!scanning) {
      uncheckedProfiles.push(profile);
    }
    if (profile.subscriptionId) {
      (subscriptionProfileIds[profile.subscriptionId] ||= []).push(profile.id);
    } else {
      manualProfileCount += 1;
    }
  });

  return { hasExportable, fastestProfile, failedProfiles, uncheckedProfiles, profileById, subscriptionProfileIds, manualProfileCount };
}

function v2rayDelaySortValue(result?: V2RayPingResult): number {
  return result?.realDelayMs || result?.latencyMs || Number.POSITIVE_INFINITY;
}

function v2rayProfileCredentialReady(profile: V2RayProfile): boolean {
  switch (normalizeV2RayProtocol(profile.protocol)) {
    case "trojan":
      return Boolean(profile.password.trim());
    case "shadowsocks":
      return Boolean(profile.shadowsocksMethod.trim() && profile.password.trim());
    case "hysteria2":
      return Boolean(profile.hysteriaAuth.trim());
    case "wireguard":
      return Boolean(profile.wireGuardSecretKey.trim() && profile.wireGuardPeerPublicKey.trim());
    case "socks":
    case "http":
      return true;
    default:
      return Boolean(profile.uuid.trim());
  }
}

function v2raySubscriptionStatusLabel(subscription: V2RaySubscription): string {
  if (subscription.lastError) {
    return subscription.lastError;
  }
  if (!subscription.lastUpdatedAt) {
    return "Never refreshed";
  }
  return `Updated ${new Date(subscription.lastUpdatedAt).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })}`;
}

function defaultV2RaySubscriptionDraft(): V2RaySubscription {
  return {
    id: "",
    name: "V2Ray Subscription",
    url: "",
    lastUpdatedAt: "",
    lastError: "",
    importedCount: 0,
  };
}

function V2RaySettingsPage({
  state,
  onState,
  onError,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const isProfileLocked = profileSelectionLocked(state.runtime);
  const fallbackDraft = useMemo(() => defaultV2RaySettingsDraft(), []);
  const activeSettings = effectiveV2RaySettingsProfile(state) || state.v2raySettingsProfiles[0] || fallbackDraft;
  const selected = state.v2raySettingsProfiles.find((profile) => profile.id === state.selectedV2RaySettingsId) || activeSettings;
  const [draft, setDraft] = useState(selected);
  const [editorOpen, setEditorOpen] = useState(false);

  useEffect(() => {
    if (!editorOpen) {
      setDraft(normalizeV2RaySettingsProfile(selected || fallbackDraft));
    }
  }, [editorOpen, fallbackDraft, selected]);

  async function saveDraft() {
    onError("");
    const profile = normalizeV2RaySettingsProfile(draft.id ? draft : { ...draft, id: makeV2RaySettingsProfileId(state.v2raySettingsProfiles) });
    try {
      const nextState = await backend.saveV2RaySettingsProfile(profile);
      onState(nextState);
      const savedProfile = nextState.v2raySettingsProfiles.find((candidate) => candidate.id === profile.id) || profile;
      setDraft(normalizeV2RaySettingsProfile(savedProfile));
      setEditorOpen(false);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function deleteDraft() {
    if (!draft.id) {
      return;
    }
    onError("");
    try {
      const nextState = await backend.deleteV2RaySettingsProfile(draft.id);
      onState(nextState);
      setEditorOpen(false);
      const nextActive = effectiveV2RaySettingsProfile(nextState);
      setDraft(normalizeV2RaySettingsProfile(nextActive || nextState.v2raySettingsProfiles[0] || fallbackDraft));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  function openSettingsProfile(profile: V2RaySettingsProfile) {
    onError("");
    setDraft(normalizeV2RaySettingsProfile(profile));
    setEditorOpen(true);
    if (isProfileLocked) {
      return;
    }
    backend.selectV2RaySettingsProfile(profile.id).then(onState).catch((err) => onError(messageFromError(err)));
  }

  function openNewSettingsProfile() {
    onError("");
    setDraft(defaultV2RaySettingsDraft());
    setEditorOpen(true);
  }

  return (
    <>
      <PageShell
        eyebrow="WhiteVPN"
        title="V2Ray Settings"
        actions={
          <Button variant="outline" onClick={openNewSettingsProfile}>
            <Plus />
            New
          </Button>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
            <div className="min-w-0">
              <p className="text-sm font-semibold">Local proxy settings</p>
              <p className="text-xs text-muted-foreground">
                {state.v2raySettingsProfiles.length} profile{state.v2raySettingsProfiles.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1040px] table-fixed text-start">
              <colgroup>
                <col className="w-[20%]" />
                <col className="w-[16%]" />
                <col className="w-[12%]" />
                <col className="w-[10%]" />
                <col className="w-[10%]" />
                <col className="w-[12%]" />
                <col className="w-[12%]" />
                <col className="w-[8%]" />
              </colgroup>
              <thead className="border-b bg-muted/20 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Listen</th>
                  <th className="px-3 py-2 font-medium">Inbound</th>
                  <th className="px-3 py-2 font-medium">LAN</th>
                  <th className="px-3 py-2 font-medium">TUN</th>
                  <th className="px-3 py-2 font-medium">System proxy</th>
                  <th className="px-3 py-2 font-medium">Enhanced Connection</th>
                  <th className="px-3 py-2 font-medium">Log level</th>
                </tr>
              </thead>
              <tbody>
                {state.v2raySettingsProfiles.map((profile) => {
                  const selectedProfile = profile.id === selected?.id;
                  return (
                    <tr
                      key={profile.id}
                      role="button"
                      tabIndex={0}
                      className={cn(
                        "cursor-pointer border-b text-sm transition-colors last:border-b-0 hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
                        selectedProfile && "bg-muted/40"
                      )}
                      onClick={() => openSettingsProfile(profile)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          openSettingsProfile(profile);
                        }
                      }}
                    >
                      <td className="min-w-0 px-3 py-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="truncate font-medium">{profile.name || "V2Ray Settings"}</span>
                          {profile.id === state.selectedV2RaySettingsId && (
                            <Badge variant="outline" className="shrink-0">
                              Selected
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="min-w-0 px-3 py-3">
                        <span className="block truncate">
                          {profile.listenIp}:{profile.listenPort}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant="secondary">{v2rayInboundLabel(profile.inboundType)}</Badge>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant={profile.allowLan ? "default" : "outline"} className={cn(!profile.allowLan && "text-muted-foreground")}>
                          {profile.allowLan ? "Allowed" : "Off"}
                        </Badge>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant={profile.tunEnabled ? "default" : "outline"} className={cn(!profile.tunEnabled && "text-muted-foreground")}>
                          {profile.tunEnabled ? "Enabled" : "Off"}
                        </Badge>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant={profile.setSystemProxy ? "default" : "outline"} className={cn(!profile.setSystemProxy && "text-muted-foreground")}>
                          {profile.setSystemProxy ? "Enabled" : "Off"}
                        </Badge>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant={profile.iranRoutingEnabled ? "default" : "outline"} className={cn(!profile.iranRoutingEnabled && "text-muted-foreground")}>
                          {profile.iranRoutingEnabled ? "Enhanced" : "Off"}
                        </Badge>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant="outline">{profile.logLevel || "WARN"}</Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </PageShell>

      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>{draft.id ? draft.name : "New V2Ray settings"}</DialogTitle>
            <DialogDescription>V2Ray local proxy</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto pr-1">
            <FieldGroup className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              <TextField label="Name" value={draft.name} onChange={(name) => setDraft({ ...draft, name })} />
              <SelectField
                label="Inbound type"
                value={draft.inboundType || "mixed"}
                onChange={(inboundType) => setDraft({ ...draft, inboundType: String(inboundType) })}
                options={[
                  ["mixed", "Mixed SOCKS/HTTP"],
                  ["socks", "SOCKS"],
                  ["http", "HTTP"],
                ]}
              />
              <SelectField
                label="Log level"
                value={draft.logLevel || "WARN"}
                onChange={(logLevel) => setDraft({ ...draft, logLevel: String(logLevel) })}
                options={[
                  ["DEBUG", "DEBUG"],
                  ["INFO", "INFO"],
                  ["WARN", "WARN"],
                  ["ERROR", "ERROR"],
                ]}
              />
              <TextField label="Listen IP" value={draft.listenIp} onChange={(listenIp) => setDraft(withV2RaySettingsListenIp(draft, listenIp))} />
              <NumberField label="Listen port" value={draft.listenPort} min={1} max={65535} onChange={(listenPort) => setDraft({ ...draft, listenPort })} />
              <ToggleField
                label="Set system proxy"
                checked={draft.setSystemProxy}
                onChange={(setSystemProxy) => setDraft({ ...draft, setSystemProxy })}
              />
              <ToggleField
                label="TUN mode"
                checked={draft.tunEnabled}
                description="Routes full-device traffic through Xray while keeping the local proxy inbound available. DNS server settings are not changed; local router DNS may remain local."
                onChange={(tunEnabled) => setDraft({ ...draft, tunEnabled })}
              />
              <NumberField
                label="TUN MTU"
                value={draft.tunMtu}
                min={576}
                max={9000}
                disabled={!draft.tunEnabled}
                onChange={(tunMtu) => setDraft({ ...draft, tunMtu })}
              />
              <ToggleField
                label="TUN IPv6"
                checked={draft.tunIpv6}
                disabled={!draft.tunEnabled}
                description="When enabled, IPv6 split-default routes are added with the TUN interface."
                onChange={(tunIpv6) => setDraft({ ...draft, tunIpv6 })}
              />
              <TextField
                label="TUN interface"
                value={draft.tunInterfaceName}
                disabled={!draft.tunEnabled}
                description="Default: WhiteDNS Tunnel on Windows, utun20 on macOS, xray0 on Linux."
                onChange={(tunInterfaceName) => setDraft({ ...draft, tunInterfaceName })}
              />
              <ToggleField
                label={enhancedConnectionLabel}
                checked={draft.iranRoutingEnabled}
                description={iranRoutingDescription}
                onChange={(iranRoutingEnabled) => setDraft({ ...draft, iranRoutingEnabled })}
              />
            </FieldGroup>
          </div>
          <DialogFooter className="sm:justify-between">
            {draft.id !== "v2ray-settings-default" && Boolean(draft.id) ? (
              <Button type="button" variant="destructive" onClick={deleteDraft} className="sm:me-auto">
                <Trash2 />
                Delete
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button type="button" variant="outline" onClick={() => setEditorOpen(false)}>
                Cancel
              </Button>
              <Button type="button" onClick={saveDraft}>
                <Save />
                Save
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function v2rayInboundLabel(inboundType: string): string {
  switch (inboundType) {
    case "socks":
      return "SOCKS";
    case "http":
      return "HTTP";
    default:
      return "Mixed";
  }
}


function withV2RaySettingsListenIp(profile: V2RaySettingsProfile, listenIp: string): V2RaySettingsProfile {
  return {
    ...profile,
    listenIp,
    allowLan: v2rayListenAllowsLan(listenIp),
  };
}

function defaultV2RaySettingsDraft(): V2RaySettingsProfile {
  return {
    id: "",
    name: "V2Ray Settings",
    listenIp: "127.0.0.1",
    allowLan: false,
    listenPort: 10888,
    inboundType: "mixed",
    setSystemProxy: true,
    tunEnabled: false,
    tunMtu: 1492,
    tunIpv6: true,
    tunInterfaceName: defaultV2RayTunInterfaceName(),
    iranRoutingEnabled: false,
    logLevel: "WARN",
  };
}

function isExportableV2RayProfile(profile: V2RayProfile): boolean {
  if (!profile.server.trim()) {
    return false;
  }
  return v2rayProfileCredentialReady(profile);
}

function FullBackupPage({
  state,
  onState,
  onError,
  onSuccess,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
}) {
  const [backupText, setBackupText] = useState("");
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restoreText, setRestoreText] = useState("");
  const restoreDisabled = !restoreText.trim() || profileSelectionLocked(state.runtime);

  async function exportBackup() {
    onError("");
    try {
      setBackupText(await backend.exportBackup());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function importBackupFile(file: File | null) {
    if (!file) {
      return;
    }
    setRestoreText(await file.text());
  }

  async function restoreBackup() {
    onError("");
    try {
      const next = await backend.importBackup(restoreText);
      onState(next);
      setRestoreText("");
      setRestoreOpen(false);
      onSuccess("Restored backup.");
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  return (
    <>
      <PageShell eyebrow="Tools" title="Full Backup">
        <Card>
          <CardHeader>
            <CardTitle>Profile Backup</CardTitle>
            <CardDescription>Export or restore all saved WhiteVPN profiles.</CardDescription>
          </CardHeader>
          <CardContent>
            <BackupRestoreSection
              restoreLocked={profileSelectionLocked(state.runtime)}
              onExportBackup={exportBackup}
              onOpenRestore={() => setRestoreOpen(true)}
            />
          </CardContent>
        </Card>
      </PageShell>

      <Dialog open={Boolean(backupText)} onOpenChange={(open) => !open && setBackupText("")}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>WhiteVPN backup.json</DialogTitle>
            <DialogDescription>Full profile backup exported as JSON.</DialogDescription>
          </DialogHeader>
          <Textarea
            readOnly
            value={backupText}
            className="h-[min(58svh,32rem)] min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
            onFocus={(event) => event.currentTarget.select()}
          />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => navigator.clipboard?.writeText(backupText)}>
              <Copy />
              Copy JSON
            </Button>
            <Button
              type="button"
              onClick={() => downloadTextFile(`whitedns-backup-${new Date().toISOString().slice(0, 10)}.json`, backupText, "application/json;charset=utf-8")}
            >
              <FileText />
              Download JSON
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={restoreOpen} onOpenChange={setRestoreOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Restore Backup</DialogTitle>
            <DialogDescription>Restore replaces saved MasterDNS, V2Ray, resolver, and settings profiles.</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 space-y-4 overflow-auto pr-1">
            <Field>
              <FieldLabel>Backup file</FieldLabel>
              <Input type="file" accept=".json,application/json,text/plain" onChange={(event) => importBackupFile(event.target.files?.[0] || null)} />
            </Field>
            <TextAreaField
              label="Backup JSON"
              value={restoreText}
              onChange={setRestoreText}
              placeholder={'{\n  "schema": "whitedns.desktop.backup",\n  "version": 1\n}'}
              className="h-[min(45svh,20rem)] min-h-0 resize-none overflow-auto font-mono text-xs"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRestoreOpen(false)}>
              Cancel
            </Button>
            <Button disabled={restoreDisabled} onClick={restoreBackup}>
              <Upload />
              Restore
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function BackupRestoreSection({
  restoreLocked,
  onExportBackup,
  onOpenRestore,
}: {
  restoreLocked: boolean;
  onExportBackup: () => void;
  onOpenRestore: () => void;
}) {
  return (
    <SettingsFieldSet legend="Backup and restore">
      <FieldGroup>
        <Field orientation="horizontal" className="items-center justify-between gap-4 rounded-lg border p-4">
          <FieldContent>
            <FieldTitle>Export full backup</FieldTitle>
            <FieldDescription>MasterDNS, V2Ray, resolvers, settings, selected profiles, and saved secrets.</FieldDescription>
          </FieldContent>
          <Button type="button" variant="outline" onClick={onExportBackup}>
            <FileText />
            Export
          </Button>
        </Field>
        <Field orientation="horizontal" className="items-center justify-between gap-4 rounded-lg border p-4">
          <FieldContent>
            <FieldTitle>Restore full backup</FieldTitle>
            <FieldDescription>Restores are available when WhiteDNS is disconnected.</FieldDescription>
          </FieldContent>
          <Button type="button" variant="outline" disabled={restoreLocked} onClick={onOpenRestore}>
            <Upload />
            Restore
          </Button>
        </Field>
      </FieldGroup>
    </SettingsFieldSet>
  );
}

function V2RayWhiteIPsPage({
  onState,
  onError,
  onSuccess,
}: {
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
}) {
  const [configText, setConfigText] = useState("");
  const [whiteIPText, setWhiteIPText] = useState("");
  const [defaultWhiteIPText, setDefaultWhiteIPText] = useState("");
  const [statusText, setStatusText] = useState("");
  const [loadingDefault, setLoadingDefault] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [generatedDialog, setGeneratedDialog] = useState<{
    configText: string;
    generated: number;
    whiteIpCount: number;
    sourceProfileCount: number;
    copyStatus: string;
  } | null>(null);
  const endpointLineCount = useMemo(() => countWhiteIPEndpointLines(whiteIPText), [whiteIPText]);
  const generateDisabled = generating || importing || loadingDefault || !configText.trim() || !whiteIPText.trim();

  useEffect(() => {
    let cancelled = false;
    setLoadingDefault(true);
    backend.getDefaultWhiteIPList()
      .then((text) => {
        if (cancelled) {
          return;
        }
        setDefaultWhiteIPText(text);
        setWhiteIPText((current) => current.trim() ? current : text);
        setStatusText("");
      })
      .catch((err) => {
        if (!cancelled) {
          const message = messageFromError(err);
          setStatusText(message);
          onError(message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoadingDefault(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function generateWhiteIPProfiles() {
    onError("");
    setStatusText("");
    setGenerating(true);
    try {
      const result = await backend.generateV2RayWhiteIpProfiles(configText, whiteIPText);
      setGeneratedDialog({ ...result, copyStatus: "" });
      setStatusText(`Generated ${result.generated} config${result.generated === 1 ? "" : "s"}.`);
    } catch (err) {
      const message = messageFromError(err);
      setStatusText(message);
      onError(message);
    } finally {
      setGenerating(false);
    }
  }

  async function importWhiteIPProfiles() {
    onError("");
    setStatusText("");
    setImporting(true);
    try {
      const result = await backend.importV2RayWhiteIpProfiles(configText, whiteIPText);
      onState(result.state);
      const profileLabel = result.imported === 1 ? "profile" : "profiles";
      const endpointLabel = result.whiteIpCount === 1 ? "endpoint" : "endpoints";
      onSuccess(`Imported ${result.imported} V2Ray ${profileLabel} from ${result.whiteIpCount} White IP ${endpointLabel}.`);
      setStatusText(`${result.sourceProfileCount} source profile${result.sourceProfileCount === 1 ? "" : "s"} converted.`);
      setGeneratedDialog(null);
    } catch (err) {
      const message = messageFromError(err);
      setStatusText(message);
      onError(message);
    } finally {
      setImporting(false);
    }
  }

  async function copyGeneratedProfiles() {
    if (!generatedDialog) {
      return;
    }
    try {
      await navigator.clipboard?.writeText(generatedDialog.configText);
      setGeneratedDialog({ ...generatedDialog, copyStatus: "Copied" });
    } catch {
      setGeneratedDialog({ ...generatedDialog, copyStatus: "Copy failed" });
    }
  }

  async function importWhiteIPFile(file: File | null) {
    if (!file) {
      return;
    }
    try {
      setWhiteIPText(await file.text());
      setStatusText(`Loaded ${file.name}.`);
    } catch (err) {
      const message = messageFromError(err);
      setStatusText(message);
      onError(message);
    }
  }

  function resetDefaultWhiteIPs() {
    setWhiteIPText(defaultWhiteIPText);
    setStatusText("Default WhiteDNS IP list restored.");
  }

  return (
    <>
    <PageShell
      eyebrow="Tools"
      title="V2Ray White IP Generator"
      actions={
        <>
          <Button type="button" variant="outline" disabled={loadingDefault || !defaultWhiteIPText} onClick={resetDefaultWhiteIPs}>
            <RotateCcw />
            Reset default
          </Button>
          <Button type="button" disabled={generateDisabled} onClick={generateWhiteIPProfiles}>
            <Share2 />
            {generating ? "Generating" : "Generate"}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <Card>
          <CardHeader>
            <CardTitle>Source config</CardTitle>
            <CardDescription>Paste one or more V2Ray share links or a WireGuard config.</CardDescription>
          </CardHeader>
          <CardContent>
            <TextAreaField
              label="V2Ray config"
              value={configText}
              onChange={setConfigText}
              placeholder={"vless://...\nvmess://...\ntrojan://...\nss://...\nhy2://..."}
              className="h-[min(50svh,28rem)] min-h-80 resize-none overflow-auto font-mono text-xs leading-relaxed"
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex min-w-0 items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle>White IP list</CardTitle>
                <CardDescription>
                  {endpointLineCount ? `${endpointLineCount} endpoint line${endpointLineCount === 1 ? "" : "s"}` : "No endpoint lines"}
                </CardDescription>
              </div>
              {loadingDefault && <Badge variant="outline">Loading</Badge>}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field>
              <FieldLabel>Import list file</FieldLabel>
              <Input
                type="file"
                accept=".txt,.lst,.conf,.config,.csv,.resolvers,text/plain"
                onChange={(event) => {
                  void importWhiteIPFile(event.target.files?.[0] || null);
                  event.currentTarget.value = "";
                }}
              />
            </Field>
            <TextAreaField
              label="Endpoints"
              value={whiteIPText}
              onChange={setWhiteIPText}
              placeholder={"# Format: host:port\n[cloudflare]\n69.84.182.49:443"}
              className="h-[min(45svh,24rem)] min-h-72 resize-none overflow-auto font-mono text-xs leading-relaxed"
            />
            {statusText && <p className="text-xs font-medium text-muted-foreground">{statusText}</p>}
          </CardContent>
        </Card>
      </div>
    </PageShell>

    <Dialog open={Boolean(generatedDialog)} onOpenChange={(open) => !open && setGeneratedDialog(null)}>
      <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Generated V2Ray White IP Profiles</DialogTitle>
          <DialogDescription>
            {generatedDialog
              ? `${generatedDialog.generated} config${generatedDialog.generated === 1 ? "" : "s"} from ${generatedDialog.whiteIpCount} White IP endpoint${generatedDialog.whiteIpCount === 1 ? "" : "s"}.`
              : "Converted V2Ray configs"}
          </DialogDescription>
        </DialogHeader>
        <Textarea
          readOnly
          value={generatedDialog?.configText || ""}
          className="h-[min(56svh,28rem)] min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
        />
        <DialogFooter className="gap-2 sm:justify-between">
          <div className="min-h-5 text-xs font-medium text-muted-foreground">
            {generatedDialog?.copyStatus || (generatedDialog ? `${generatedDialog.sourceProfileCount} source profile${generatedDialog.sourceProfileCount === 1 ? "" : "s"}` : "")}
          </div>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button type="button" variant="outline" onClick={() => setGeneratedDialog(null)}>
              Close
            </Button>
            <Button type="button" variant="outline" disabled={!generatedDialog?.configText} onClick={copyGeneratedProfiles}>
              <Copy />
              Copy
            </Button>
            <Button type="button" disabled={!generatedDialog || importing} onClick={importWhiteIPProfiles}>
              <Download />
              {importing ? "Importing" : "Import as V2Ray profiles"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    </>
  );
}

function ValidatorPage({
  state,
  onState,
  onAppState,
  onError,
}: {
  state: ValidatorState;
  onState: (state: ValidatorState) => void;
  onAppState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const [mode, setMode] = useState<"quick" | "bulk">("bulk");
  const [host, setHost] = useState("");
  const [ports, setPorts] = useState("53");
  const [sni, setSni] = useState("");
  const [rangeOptions, setRangeOptions] = useState<ValidatorRangeOption[]>([]);
  const [rangeSource, setRangeSource] = useState<"default" | "imported">("default");
  const [importedRangeOptions, setImportedRangeOptions] = useState<ValidatorRangeOption[]>([]);
  const [importedFileName, setImportedFileName] = useState("");
  const [importStatusText, setImportStatusText] = useState("");
  const [selectedRanges, setSelectedRanges] = useState<string[]>([]);
  const [rangeQuery, setRangeQuery] = useState("");
  const [rangePortText, setRangePortText] = useState(defaultValidatorRangePorts.join(", "));
  const [rangeStatusText, setRangeStatusText] = useState("");
  const [rangesLoading, setRangesLoading] = useState(false);
  const [options, setOptions] = useState<ValidatorOptions>(defaultValidatorOptions);
  const [httpPaths, setHttpPaths] = useState("/");
  const [inputError, setInputError] = useState("");
  const [resultFiles, setResultFiles] = useState<ValidatorResultFile[]>([]);
  const [filesLoading, setFilesLoading] = useState(false);
  const [filesStatusText, setFilesStatusText] = useState("");
  const [now, setNow] = useState(Date.now());
  const running = state.status === "running";
  const progress = state.total > 0 ? Math.round((state.completed / state.total) * 100) : 0;
  const timeEstimate = useMemo(() => formatValidatorTimeEstimate(state, now), [now, state.completed, state.finishedAt, state.paused, state.startedAt, state.status, state.total]);
  const selectedRangeSet = useMemo(() => new Set(selectedRanges), [selectedRanges]);
  const defaultRangeSet = useMemo(() => new Set(rangeOptions.map((option) => option.range)), [rangeOptions]);
  const activeRangeOptions = rangeSource === "imported" ? importedRangeOptions : rangeOptions;
  const filteredRanges = useMemo(() => {
    const query = rangeQuery.trim().toLowerCase();
    if (!query) {
      return activeRangeOptions;
    }
    return activeRangeOptions.filter((option) => option.range.toLowerCase().includes(query));
  }, [activeRangeOptions, rangeQuery]);
  const rangeHostCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const option of rangeOptions) {
      counts.set(option.range, option.hostCount);
    }
    for (const option of importedRangeOptions) {
      counts.set(option.range, option.hostCount);
    }
    return counts;
  }, [importedRangeOptions, rangeOptions]);
  const rangePortParse = useMemo(() => parseValidatorPortList(rangePortText), [rangePortText]);
  const rangePorts = rangePortParse.ports;
  const selectedRangeHostCount = useMemo(
    () => selectedRanges.reduce((total, range) => total + (rangeHostCounts.get(range) || 0), 0),
    [rangeHostCounts, selectedRanges]
  );
  const selectedRangeEndpointCount = useMemo(
    () => selectedRangeHostCount * rangePorts.length,
    [rangePorts.length, selectedRangeHostCount]
  );
  const rangeSelectionTooLarge = selectedRangeEndpointCount > maxValidatorSelectedRangeHosts;

  useEffect(() => {
    let cancelled = false;
    setRangesLoading(true);
    backend.getDefaultValidatorRanges()
      .then((ranges) => {
        if (cancelled) {
          return;
        }
        setRangeOptions(ranges);
        setRangeStatusText("");
      })
      .catch((err) => {
        if (cancelled) {
          return;
        }
        setRangeStatusText(messageFromError(err));
      })
      .finally(() => {
        if (!cancelled) {
          setRangesLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void loadResultFiles();
  }, []);

  useEffect(() => {
    if (state.status === "completed" || state.status === "cancelled" || state.status === "failed") {
      void loadResultFiles();
    }
  }, [state.status, state.finishedAt]);

  useEffect(() => {
    if (!running) {
      setNow(Date.now());
      return;
    }
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  async function loadResultFiles() {
    setFilesLoading(true);
    try {
      setResultFiles(await backend.listValidatorResultFiles());
      setFilesStatusText("");
    } catch (err) {
      const message = messageFromError(err);
      setFilesStatusText(message);
      onError(message);
    } finally {
      setFilesLoading(false);
    }
  }

  async function openResultFile(name: string) {
    try {
      await backend.openValidatorResultFile(name);
      setFilesStatusText(`Opened ${name}.`);
    } catch (err) {
      const message = messageFromError(err);
      setFilesStatusText(message);
      onError(message);
    }
  }

  async function deleteResultFile(name: string) {
    try {
      setResultFiles(await backend.deleteValidatorResultFile(name));
      setFilesStatusText(`Deleted ${name}.`);
    } catch (err) {
      const message = messageFromError(err);
      setFilesStatusText(message);
      onError(message);
    }
  }

  async function startScan() {
    setInputError("");
    try {
      const normalizedOptions = {
        ...options,
        httpPaths: httpPaths.split(/[\s,]+/).map((path) => path.trim()).filter(Boolean),
      };
      const next = mode === "bulk"
        ? await backend.startValidatorRangeScan({
          mode,
          ranges: selectedRanges,
          ports: rangePorts,
          sni,
          options: normalizedOptions,
        })
        : await backend.startValidatorScan({
          mode,
          endpoints: parseQuickValidatorEndpoints(host, ports, sni),
          options: normalizedOptions,
        });
      onState(next);
      void loadResultFiles();
    } catch (err) {
      const message = messageFromError(err);
      setInputError(message);
      onError(message);
    }
  }

  async function cancelScan() {
    try {
      onState(await backend.cancelValidatorScan());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function setPaused(paused: boolean) {
    try {
      onState(await backend.setValidatorPaused(paused));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function clearResults() {
    setInputError("");
    try {
      onState(await backend.clearValidatorResults());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function importBulkFile(file: File | null) {
    if (!file) {
      return;
    }
    setMode("bulk");
    setRangeSource("imported");
    setInputError("");
    setImportStatusText("Importing file");
    try {
      const text = await file.text();
      const result = await backend.parseValidatorRangeInput(text);
      const nextImportedSet = new Set(result.ranges.map((option) => option.range));
      setImportedFileName(file.name);
      setImportedRangeOptions(result.ranges);
      setSelectedRanges((current) => current.filter((range) => defaultRangeSet.has(range) || nextImportedSet.has(range)));

      const summary = [
        `${formatCount(result.ranges.length)} imported`,
        result.totalCount ? `${formatCount(result.totalCount)} input${result.totalCount === 1 ? "" : "s"}` : "",
        result.duplicateCount ? `${formatCount(result.duplicateCount)} duplicate${result.duplicateCount === 1 ? "" : "s"}` : "",
        result.invalidCount ? `${formatCount(result.invalidCount)} invalid` : "",
      ].filter(Boolean).join(" · ");
      const invalidSample = result.invalid.length ? ` Invalid: ${result.invalid.join(", ")}${result.invalidCount > result.invalid.length ? ", ..." : ""}` : "";
      setImportStatusText(`${summary || "No input found."}${invalidSample}`);
      if (!result.ranges.length) {
        setInputError(result.totalCount ? "Imported file contains no valid IPv4 or CIDR ranges." : "Imported file is empty.");
      }
    } catch (err) {
      const message = messageFromError(err);
      setImportStatusText(message);
      setInputError(message);
      onError(message);
    }
  }

  function toggleRange(range: string) {
    setSelectedRanges((current) => current.includes(range)
      ? current.filter((item) => item !== range)
      : [...current, range]
    );
  }

  function selectFilteredRanges() {
    setSelectedRanges((current) => {
      const next = new Set(current);
      for (const option of filteredRanges) {
        next.add(option.range);
      }
      return Array.from(next);
    });
  }

  function clearImportedRanges() {
    setImportedRangeOptions([]);
    setImportedFileName("");
    setImportStatusText("");
    setSelectedRanges((current) => current.filter((range) => defaultRangeSet.has(range)));
  }

  function renderRangeList(options: ValidatorRangeOption[], loading: boolean, emptyText: string) {
    return (
      <ScrollArea className="h-72 rounded-lg border">
        <div className="divide-y">
          {loading && !options.length ? (
            Array.from({ length: 8 }).map((_, index) => (
              <div key={index} className="flex items-center gap-3 px-3 py-2">
                <Skeleton className="size-4 rounded-sm" />
                <Skeleton className="h-4 flex-1" />
                <Skeleton className="h-4 w-20" />
              </div>
            ))
          ) : options.length ? (
            options.map((option) => {
              const selected = selectedRangeSet.has(option.range);
              return (
                <button
                  key={option.range}
                  type="button"
                  disabled={running}
                  className={cn(
                    "flex w-full min-w-0 items-center gap-3 px-3 py-2 text-start text-sm transition-colors hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-60",
                    selected && "bg-primary/5"
                  )}
                  onClick={() => toggleRange(option.range)}
                >
                  <input
                    type="checkbox"
                    checked={selected}
                    readOnly
                    tabIndex={-1}
                    className="size-4 shrink-0 accent-primary"
                  />
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{option.range}</span>
                  <span className="shrink-0 text-xs font-medium text-muted-foreground">{formatCount(option.hostCount)}</span>
                </button>
              );
            })
          ) : (
            <div className="px-3 py-8 text-center text-sm text-muted-foreground">{emptyText}</div>
          )}
        </div>
      </ScrollArea>
    );
  }

  return (
    <PageShell
      eyebrow="Validator"
      title="Tunnel Validator"
    >
      <div className="grid gap-4 xl:grid-cols-[420px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Endpoint input</CardTitle>
            <CardDescription>Test endpoints from {defaultValidatorRangeCSVName}.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={mode} onValueChange={(value) => setMode(value as "quick" | "bulk")}>
              <TabsList>
                <TabsTrigger value="quick">Quick</TabsTrigger>
                <TabsTrigger value="bulk">Bulk</TabsTrigger>
              </TabsList>
              <TabsContent value="quick" className="space-y-4 pt-4">
                <TextField label="Host" value={host} onChange={setHost} placeholder="example.com" />
                <TextField label="Ports" value={ports} onChange={setPorts} placeholder="53, 443" />
                <TextField label="SNI" value={sni} onChange={setSni} placeholder="optional.example.com" />
              </TabsContent>
              <TabsContent value="bulk" className="space-y-4 pt-4">
                <FieldSet className="gap-3">
                  <div className="flex min-w-0 items-center justify-between gap-3">
                    <FieldTitle className="text-base">IPv4 sources</FieldTitle>
                    <Badge variant="outline">
                      {selectedRanges.length ? `${formatCount(selectedRanges.length)} selected` : `${formatCount(rangeHostCounts.size)} ranges`}
                    </Badge>
                  </div>
                  <div className="space-y-3">
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <Button type="button" size="sm" variant="outline" disabled={running || !filteredRanges.length} onClick={selectFilteredRanges}>
                        <CheckCircle2 />
                        Select shown
                      </Button>
                      <Button type="button" size="sm" variant="outline" disabled={running || !selectedRanges.length} onClick={() => setSelectedRanges([])}>
                        <X />
                        Clear ranges
                      </Button>
                      <span className="text-xs font-medium text-muted-foreground">
                        {selectedRanges.length ? `${formatCount(selectedRangeEndpointCount)} endpoints` : rangesLoading ? "Loading" : "No ranges selected"}
                      </span>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <FieldLabel>Ports</FieldLabel>
                        <span className="text-xs text-muted-foreground">
                          {rangePorts.length ? `${rangePorts.length} port${rangePorts.length === 1 ? "" : "s"}` : "No ports"}
                        </span>
                      </div>
                      <Input
                        value={rangePortText}
                        disabled={running}
                        placeholder="443, 2053, 2083, 2087, 2096, 8443"
                        onChange={(event) => setRangePortText(event.target.value)}
                      />
                      <FieldDescription>Comma or space separated. Each selected range is scanned once per port.</FieldDescription>
                    </div>
                  </div>
                  {rangeSelectionTooLarge && (
                    <Alert variant="destructive">
                      <AlertCircle />
                      <AlertTitle>Range selection too large</AlertTitle>
                      <AlertDescription>Select at most {formatCount(maxValidatorSelectedRangeHosts)} endpoints.</AlertDescription>
                    </Alert>
                  )}
                  {!rangePorts.length && (
                    <Alert variant="destructive">
                      <AlertCircle />
                      <AlertTitle>No ports selected</AlertTitle>
                      <AlertDescription>Select at least one port to scan each range.</AlertDescription>
                    </Alert>
                  )}
                  {rangePortParse.error && (
                    <Alert variant="destructive">
                      <AlertCircle />
                      <AlertTitle>Invalid port list</AlertTitle>
                      <AlertDescription>{rangePortParse.error}</AlertDescription>
                    </Alert>
                  )}
                  <Tabs
                    value={rangeSource}
                    onValueChange={(value) => {
                      setRangeSource(value as "default" | "imported");
                      setRangeQuery("");
                    }}
                  >
                    <TabsList className="grid w-full grid-cols-2">
                      <TabsTrigger value="default">Default list</TabsTrigger>
                      <TabsTrigger value="imported">Imported file</TabsTrigger>
                    </TabsList>
                    <TabsContent value="default" className="space-y-3 pt-3">
                      <Input
                        value={rangeQuery}
                        disabled={running}
                        placeholder="Filter default ranges"
                        onChange={(event) => setRangeQuery(event.target.value)}
                      />
                      {rangeStatusText && (
                        <Alert variant="destructive">
                          <AlertCircle />
                          <AlertTitle>Default ranges unavailable</AlertTitle>
                          <AlertDescription>{rangeStatusText}</AlertDescription>
                        </Alert>
                      )}
                      {renderRangeList(filteredRanges, rangesLoading, rangeQuery.trim() ? "No default ranges match" : "No default ranges")}
                    </TabsContent>
                    <TabsContent value="imported" className="space-y-3 pt-3">
                      <div className="space-y-2">
                        <Input
                          type="file"
                          accept=".txt,.csv,text/plain,text/csv"
                          disabled={running}
                          onChange={(event) => {
                            void importBulkFile(event.target.files?.[0] || null);
                            event.currentTarget.value = "";
                          }}
                        />
                        <FieldDescription>IP or CIDR range, separated by comma or line.</FieldDescription>
                        {importedFileName && (
                          <div className="flex min-w-0 items-center gap-2 text-xs font-medium text-muted-foreground">
                            <FileText className="size-3.5 shrink-0" />
                            <span className="min-w-0 truncate">{importedFileName}</span>
                          </div>
                        )}
                        {importStatusText && <p className="text-xs font-medium text-muted-foreground">{importStatusText}</p>}
                        <Button type="button" size="sm" variant="outline" disabled={running || (!importedRangeOptions.length && !importedFileName)} onClick={clearImportedRanges}>
                          <X />
                          Clear imported file
                        </Button>
                      </div>
                      <Input
                        value={rangeQuery}
                        disabled={running}
                        placeholder="Filter imported ranges"
                        onChange={(event) => setRangeQuery(event.target.value)}
                      />
                      {renderRangeList(filteredRanges, false, rangeQuery.trim() ? "No imported ranges match" : "Import a file to show ranges")}
                    </TabsContent>
                  </Tabs>
                </FieldSet>
              </TabsContent>
            </Tabs>

            {inputError && (
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>Validator input error</AlertTitle>
                <AlertDescription>{inputError}</AlertDescription>
              </Alert>
            )}

            <Separator />
            <FieldSet>
              <FieldTitle className="text-base">Options</FieldTitle>
              <FieldGroup className="grid gap-3 sm:grid-cols-2">
                <NumberField label="Retries" value={options.retries} min={1} max={8} onChange={(retries) => setOptions({ ...options, retries })} />
                <NumberField label="Timeout ms" value={options.timeoutMillis} min={250} max={60000} onChange={(timeoutMillis) => setOptions({ ...options, timeoutMillis })} />
                <NumberField
                  label="Scan workers"
                  value={validatorWorkerCountOption(options)}
                  min={1}
                  max={maxValidatorWorkers}
                  onChange={(workerCount) => {
                    const nextWorkerCount = clampValidatorWorkers(workerCount);
                    setOptions({ ...options, workerCount: nextWorkerCount, adaptiveLimit: nextWorkerCount });
                  }}
                />
                <TextField label="HTTP paths" value={httpPaths} onChange={setHttpPaths} placeholder="/, /health" />
              </FieldGroup>
              <FieldGroup className="grid gap-1 pt-2 sm:grid-cols-2">
                <ToggleField label="UDP" checked={options.enableUdp} onChange={(enableUdp) => setOptions({ ...options, enableUdp })} />
                <ToggleField label="QUIC/H3" checked={options.enableQuic} onChange={(enableQuic) => setOptions({ ...options, enableQuic })} />
                <ToggleField label="DNS" checked={options.enableDns} onChange={(enableDns) => setOptions({ ...options, enableDns })} />
                <ToggleField label="WebSocket" checked={options.enableWebSocket} onChange={(enableWebSocket) => setOptions({ ...options, enableWebSocket })} />
                <ToggleField label="Insecure TLS" checked={options.allowInsecureCert} onChange={(allowInsecureCert) => setOptions({ ...options, allowInsecureCert })} />
              </FieldGroup>
            </FieldSet>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader className="gap-3">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <StatusDot status={validatorStatusDot(state.status, state.paused)} />
                    {validatorStatusLabel(state.status, state.paused)}
                  </CardTitle>
                  <CardDescription>
                    {state.total > 0 ? `${state.completed} of ${state.total} endpoints complete` : "No validation running"}
                  </CardDescription>
                  {state.resultsFileName && (
                    <div className="mt-2 flex min-w-0 flex-wrap items-center gap-2 text-xs font-medium text-muted-foreground">
                      <FileText className="size-3.5 shrink-0" />
                      <span className="min-w-0 truncate">{state.resultsFileName}</span>
                      <span className="tabular-nums">{formatCount(state.resultsFileRows || 0)} CSV rows</span>
                      {(state.resultsFileCount || 0) > 1 && (
                        <span className="tabular-nums">file {state.resultsFilePart || 1} of {state.resultsFileCount}</span>
                      )}
                    </div>
                  )}
                  {(state.requestedWorkers || state.effectiveWorkers || state.workerCeiling) > 0 && state.status !== "idle" && (
                    <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2 text-xs font-medium text-muted-foreground">
                      <Cpu className="size-3.5 shrink-0" />
                      <span className="tabular-nums">
                        workers {formatCount(state.effectiveWorkers || state.requestedWorkers || 0)}
                        {state.workerCeiling ? ` / ${formatCount(state.workerCeiling)} ceiling` : ""}
                        {state.requestedWorkers && state.requestedWorkers !== state.effectiveWorkers ? ` · requested ${formatCount(state.requestedWorkers)}` : ""}
                      </span>
                      {(state.pressureEvents || 0) > 0 && (
                        <span className="tabular-nums">{formatCount(state.pressureEvents)} pressure events</span>
                      )}
                    </div>
                  )}
                  {timeEstimate && (
                    <div className="mt-1 flex min-w-0 flex-wrap items-center gap-2 text-xs font-medium text-muted-foreground">
                      <Activity className="size-3.5 shrink-0" />
                      <span className="tabular-nums">{timeEstimate}</span>
                    </div>
                  )}
                </div>
                <div className="flex flex-wrap gap-2 lg:justify-end">
                  <Button variant="outline" disabled={running || (state.status === "idle" && state.completed === 0 && !state.resultsFileName)} onClick={clearResults}>
                    <Trash2 />
                    Clear
                  </Button>
                  <Button variant="outline" disabled={!running || state.paused} onClick={() => setPaused(true)}>
                    <Pause />
                    Pause
                  </Button>
                  <Button variant="outline" disabled={!running || !state.paused} onClick={() => setPaused(false)}>
                    <Play />
                    Resume
                  </Button>
                  <Button variant="outline" disabled={!running} onClick={cancelScan}>
                    <Square />
                    Cancel
                  </Button>
                  <Button disabled={running || rangeSelectionTooLarge || (mode === "bulk" && (!rangePorts.length || Boolean(rangePortParse.error)))} onClick={startScan}>
                    <Search />
                    Scan
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <Progress value={progress} />
              <div className="grid gap-3 sm:grid-cols-5">
                <Metric label="A+" value={formatCount(state.gradeAPlus || 0)} compact />
                <Metric label="A" value={formatCount(state.gradeA || 0)} compact />
                <Metric label="B" value={formatCount(state.gradeB || 0)} compact />
                <Metric label="C" value={formatCount(state.gradeC || 0)} compact />
                <Metric label="F" value={formatCount(state.gradeF || 0)} compact />
              </div>
              {state.error && (
                <Alert variant="destructive">
                  <AlertCircle />
                  <AlertTitle>Validator failed</AlertTitle>
                  <AlertDescription>{state.error}</AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          <ValidatorFiles
            files={resultFiles}
            loading={filesLoading}
            statusText={filesStatusText}
            onRefresh={loadResultFiles}
            onOpen={openResultFile}
            onDelete={deleteResultFile}
          />
        </div>
      </div>
    </PageShell>
  );
}

function ValidatorFiles({
  files,
  loading,
  statusText,
  onRefresh,
  onOpen,
  onDelete,
}: {
  files: ValidatorResultFile[];
  loading: boolean;
  statusText: string;
  onRefresh: () => Promise<void>;
  onOpen: (name: string) => Promise<void>;
  onDelete: (name: string) => Promise<void>;
}) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle>Files</CardTitle>
            <CardDescription>Previous validator CSV scans. Files stay on disk until deleted.</CardDescription>
          </div>
          <Button type="button" variant="outline" onClick={onRefresh} disabled={loading}>
            <RotateCcw />
            Refresh
          </Button>
        </div>
        {statusText && <p className="text-xs font-medium text-muted-foreground">{statusText}</p>}
      </CardHeader>
      <CardContent>
        {!files.length ? (
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <FileText />
              </EmptyMedia>
              <EmptyTitle>No CSV files</EmptyTitle>
              <EmptyDescription>Validator runs will appear here after they start.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="overflow-x-auto rounded-lg border">
            <div className="min-w-[720px]">
              <div className="grid grid-cols-[minmax(220px,1fr)_92px_92px_110px_128px] items-center gap-2 border-b bg-muted/80 px-3 py-2 text-[10px] font-semibold uppercase text-muted-foreground">
                <div>File</div>
                <div>Rows</div>
                <div>Status</div>
                <div>Size</div>
                <div className="text-end">Actions</div>
              </div>
              <div className="divide-y">
                {files.map((file) => (
                  <div key={file.name} className="grid grid-cols-[minmax(220px,1fr)_92px_92px_110px_128px] items-center gap-2 px-3 py-2 text-sm">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs font-medium">{file.name}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {formatValidatorFileTime(file.startedAt || file.modifiedAt)}
                        {file.completed > 0 || file.total > 0 ? ` · ${formatCount(file.completed)} / ${formatCount(file.total)}` : ""}
                      </p>
                    </div>
                    <div className="text-xs tabular-nums text-muted-foreground">{formatCount(file.rows || 0)}</div>
                    <Badge variant={file.status === "failed" ? "destructive" : "outline"} className="w-fit text-[11px]">
                      {file.status || "saved"}
                    </Badge>
                    <div className="text-xs tabular-nums text-muted-foreground">{formatBytes(file.sizeBytes || 0)}</div>
                    <div className="flex justify-end gap-1">
                      <Button type="button" variant="ghost" size="xs" onClick={() => onOpen(file.name)}>
                        <ExternalLink />
                        Open
                      </Button>
                      <Button type="button" variant="ghost" size="xs" onClick={() => onDelete(file.name)}>
                        <Trash2 />
                        Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function LogsPage({
  runtime,
  runtimeType,
  title: titleOverride,
  description: descriptionOverride,
  onState,
  onError,
}: {
  runtime: RuntimeStatus;
  runtimeType: RuntimeType;
  title?: string;
  description?: string;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLowerCase();
  const runtimeLogs = runtimeType === "v2ray"
    ? Array.isArray(runtime.v2rayLogs) ? runtime.v2rayLogs : []
    : Array.isArray(runtime.masterDnsLogs) ? runtime.masterDnsLogs : [];
  const logs = normalizedQuery
    ? runtimeLogs.filter((line) => line.toLowerCase().includes(normalizedQuery))
    : runtimeLogs;
  // Named after what is running rather than what used to. The app runs mihomo;
  // Xray survives only behind WHITEVPN_ENGINE=xray, so naming the page after it
  // describes almost nobody's session.
  const title = titleOverride || "Diagnostics";
  const description = descriptionOverride || "Engine output and health checks.";
  const pageRuntimeActive = normalizeRuntimeType(runtime.runtimeType) === runtimeType;
  const pageStatus = pageRuntimeActive ? runtime.status : "disconnected";

  async function copyLogs() {
    try {
      await navigator.clipboard?.writeText(logs.join("\n"));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function saveLogsFile() {
    onError("");
    try {
      await backend.saveRuntimeLogs(logs.join("\n"));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function clearLogs() {
    onError("");
    try {
      onState(await backend.clearRuntimeLogs(runtimeType));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  return (
    <PageShell
      eyebrow="Logs"
      title={title}
      actions={
        <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-end">
          <div className="relative w-full min-w-0 sm:w-80">
            <Search className="absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input className="ps-8" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search logs" />
          </div>
          <Button type="button" variant="outline" onClick={copyLogs} disabled={!logs.length}>
            <Copy />
            Copy logs
          </Button>
          <Button type="button" variant="outline" onClick={saveLogsFile} disabled={!logs.length}>
            <Download />
            Save log
          </Button>
          <Button type="button" variant="outline" onClick={clearLogs} disabled={!runtimeLogs.length}>
            <Trash2 />
            Clear logs
          </Button>
        </div>
      }
    >
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <StatusDot status={pageStatus} />
            {statusLabel(pageStatus)}
          </CardTitle>
          <CardDescription className="break-words [overflow-wrap:anywhere]">{description}</CardDescription>
        </CardHeader>
      </Card>

      <Card className="min-w-0 max-w-full">
        <CardContent className="min-w-0 overflow-hidden">
          <ScrollArea className="h-[calc(100svh-18rem)] min-h-96 min-w-0 max-w-full" viewportClassName="min-w-0">
            {logs.length === 0 ? (
              <Empty className="h-80 border">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <ScrollText />
                  </EmptyMedia>
                  <EmptyTitle>No logs found</EmptyTitle>
                  <EmptyDescription>{description}</EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : (
              <div className="w-max min-w-full space-y-2 pr-3 pb-3">
                {logs.map((line, index) => (
                  <code
                    key={`${line}-${index}`}
                    className={cn(
                      "block min-w-full rounded-lg border px-3 py-2 font-mono text-xs leading-relaxed whitespace-pre",
                      logLineToneClass(line),
                      index === 0 && "ring-1 ring-foreground/10"
                    )}
                  >
                    {line}
                  </code>
                ))}
              </div>
            )}
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        </CardContent>
      </Card>
    </PageShell>
  );
}

function logLineToneClass(line: string): string {
  const normalized = ` ${line.toLowerCase()} `;
  if (normalized.includes("[error]") || normalized.includes(" error ") || normalized.includes(" failed") || normalized.includes("❌")) {
    return "border-red-200 bg-red-50 text-red-950 dark:border-[#7f1d1d]/70 dark:bg-[#2a1111] dark:text-[#fecaca]";
  }
  if (normalized.includes("[warn]") || normalized.includes(" warn ") || normalized.includes(" warning ") || normalized.includes("⚠")) {
    return "border-amber-200 bg-amber-50 text-amber-950 dark:border-[#92400e]/70 dark:bg-[#271807] dark:text-[#fde68a]";
  }
  if (normalized.includes("[debug]") || normalized.includes(" debug ")) {
    return "border-violet-200 bg-violet-50 text-violet-950 dark:border-[#6d28d9]/70 dark:bg-[#1d1533] dark:text-[#ddd6fe]";
  }
  if (normalized.includes("[info]") || normalized.includes(" info ") || normalized.includes("✅")) {
    return "border-emerald-200 bg-emerald-50 text-emerald-950 dark:border-[#047857]/70 dark:bg-[#06251f] dark:text-[#6ee7b7]";
  }
  return "border-border bg-muted/40 text-foreground dark:border-white/10 dark:bg-[#171717] dark:text-[#e5e5e5]";
}

function PageShell({
  eyebrow,
  title,
  actions,
  children,
}: {
  eyebrow: string;
  title: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="flex min-w-0 flex-col gap-4">
      <header className="flex min-w-0 flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <p className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{eyebrow}</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight">{title}</h1>
        </div>
        {actions && <div className="flex min-w-0 flex-wrap gap-2">{actions}</div>}
      </header>
      {children}
    </section>
  );
}


function SettingsFieldSet({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <FieldSet>
      <FieldTitle className="text-base">{legend}</FieldTitle>
      <Separator />
      <FieldGroup className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{children}</FieldGroup>
    </FieldSet>
  );
}

function Metric({ label, value, compact = false }: { label: string; value: string; compact?: boolean }) {
  return (
    <Card size="sm" className={compact ? "bg-muted/30" : undefined}>
      <CardContent>
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        <p className="mt-2 break-words text-xl font-semibold tracking-tight">{value}</p>
      </CardContent>
    </Card>
  );
}

function TextField({
  label,
  value,
  placeholder,
  description,
  error,
  disabled,
  onChange,
}: {
  label: string;
  value: string;
  placeholder?: string;
  description?: string;
  error?: string;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <Field data-invalid={Boolean(error)} data-disabled={disabled || undefined}>
      <FieldLabel>{label}</FieldLabel>
      <Input
        value={value}
        placeholder={placeholder}
        disabled={disabled}
        aria-invalid={Boolean(error)}
        onChange={(event) => onChange(event.target.value)}
      />
      {description && <FieldDescription>{description}</FieldDescription>}
      <FieldError>{error}</FieldError>
    </Field>
  );
}

function NumberField({
  label,
  value,
  step,
  min,
  max,
  disabled,
  description,
  onChange,
}: {
  label: string;
  value: number;
  step?: string;
  min?: number;
  max?: number;
  disabled?: boolean;
  description?: string;
  onChange: (value: number) => void;
}) {
  return (
    <Field data-disabled={disabled || undefined}>
      <FieldLabel>{label}</FieldLabel>
      <Input
        type="number"
        step={step}
        min={min}
        max={max}
        disabled={disabled}
        value={Number.isFinite(value) ? value : 0}
        onChange={(event) => onChange(Number(event.target.value))}
      />
      {description && <FieldDescription>{description}</FieldDescription>}
    </Field>
  );
}

function TextAreaField({
  label,
  value,
  placeholder,
  className,
  onChange,
}: {
  label: string;
  value: string;
  placeholder?: string;
  className?: string;
  onChange: (value: string) => void;
}) {
  return (
    <Field>
      <FieldLabel>{label}</FieldLabel>
      <Textarea
        value={value}
        placeholder={placeholder}
        className={className}
        onChange={(event) => onChange(event.target.value)}
      />
    </Field>
  );
}

function ToggleField({
  label,
  checked,
  description,
  disabled,
  onChange,
}: {
  label: string;
  checked: boolean;
  description?: string;
  disabled?: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <Field orientation="horizontal" className="items-center py-2" data-disabled={disabled || undefined}>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onChange} />
      <FieldContent>
        <FieldLabel>{label}</FieldLabel>
        {description && <FieldDescription className="whitespace-pre-line">{description}</FieldDescription>}
      </FieldContent>
    </Field>
  );
}

function SelectField<T extends string | number>({
  label,
  value,
  options,
  disabled,
  description,
  onChange,
}: {
  label: string;
  value: T;
  options: Array<[T, string]>;
  disabled?: boolean;
  description?: string;
  onChange: (value: T) => void;
}) {
  return (
    <Field>
      <FieldLabel>{label}</FieldLabel>
      <Select value={String(value)} disabled={disabled} onValueChange={(nextValue) => onChange(nextValue as T)}>
        <SelectTrigger className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([optionValue, optionLabel]) => (
            <SelectItem key={String(optionValue)} value={String(optionValue)}>
              {optionLabel}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {description && <FieldDescription>{description}</FieldDescription>}
    </Field>
  );
}

function StatusDot({ status, className }: { status: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-block rounded-full ring-4 shrink-0",
        status === "connected" && "bg-emerald-500 ring-emerald-100",
        (status === "connecting" || status === "stopping" || status === "parallel-testing") && "bg-emerald-300 ring-emerald-50",
        status === "failed" && "bg-red-300 ring-red-50",
        (status === "disconnected" || !status) && "bg-muted-foreground ring-muted",
        className || "size-2.5"
      )}
    />
  );
}

function statusCardTone(status: string): string {
  switch (status) {
    case "connected":
      return "border-[var(--connected-card-border)] bg-[var(--connected-card-bg)]";
    case "connecting":
    case "stopping":
    case "parallel-testing":
      return "border-[var(--connecting-card-border)] bg-[var(--connecting-card-bg)]";
    case "failed":
      return "border-red-100 bg-red-50";
    default:
      return "bg-card";
  }
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "failed") {
    return "destructive";
  }
  if (status === "connected") {
    return "default";
  }
  if (status === "connecting" || status === "stopping" || status === "parallel-testing") {
    return "outline";
  }
  return "secondary";
}

function statusLabel(status: string): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "connecting":
      return "Connecting";
    case "stopping":
      return "Disconnecting";
    case "parallel-testing":
      return "Parallel Testing";
    case "failed":
      return "Failed";
    default:
      return "Disconnected";
  }
}

// translatedStatusLabel is statusLabel for the screens that have been keyed.
// Anything without a key falls back to the English label rather than to the key.
function translatedStatusLabel(t: TranslateFn, status: string): string {
  switch (status) {
    case "connected":
      return t("status.connected");
    case "connecting":
      return t("status.connecting");
    case "stopping":
      return t("status.stopping");
    case "failed":
      return t("status.failed");
    case "disconnected":
      return t("status.disconnected");
    default:
      return statusLabel(status);
  }
}

function progressLabel(phase: string, percent: number): string {
  if (!phase) {
    return "Idle";
  }
  if (phase === "ready") {
    return "Ready";
  }
  return `${phase} ${percent || 0}%`;
}

function formatSpeed(value: number): string {
  return `${formatBytes(value)}/s`;
}

function formatCount(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString() : "0";
}

function formatBytes(value: number): string {
  const units = ["D", "KB", "MB", "GB", "TB"];
  let amount = Math.max(0, value || 0);
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  const digits = index === 0 || amount >= 100 ? 0 : 1;
  return `${amount.toFixed(digits)} ${units[index]}`;
}

function formatValidatorFileTime(value: number): string {
  if (!value) {
    return "Unknown time";
  }
  return new Date(value).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatValidatorTimeEstimate(state: ValidatorState, now: number): string {
  if (!state.startedAt) {
    return "";
  }
  const endedAt = state.finishedAt || now;
  const elapsedMs = Math.max(0, endedAt - state.startedAt);
  if (state.status !== "running") {
    return `Elapsed ${formatCompactDuration(elapsedMs)}`;
  }
  if (state.paused) {
    return `Elapsed ${formatCompactDuration(elapsedMs)} · paused`;
  }
  if (state.completed <= 0 || state.total <= 0 || elapsedMs <= 0) {
    return `Elapsed ${formatCompactDuration(elapsedMs)} · estimating`;
  }
  const ratePerSecond = state.completed / Math.max(1, elapsedMs / 1000);
  const remaining = Math.max(0, state.total - state.completed);
  const remainingMs = ratePerSecond > 0 ? (remaining / ratePerSecond) * 1000 : 0;
  if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
    return `Elapsed ${formatCompactDuration(elapsedMs)} · ${formatCount(Math.round(ratePerSecond))}/s`;
  }
  return `ETA ${formatCompactDuration(remainingMs)} · ${formatCount(Math.round(ratePerSecond))}/s`;
}

function formatCompactDuration(valueMs: number): string {
  const totalSeconds = Math.max(0, Math.round(valueMs / 1000));
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds.toString().padStart(2, "0")}s`;
  }
  return `${seconds}s`;
}

function parseValidatorPortList(text: string): { ports: number[]; error: string } {
  const tokens = text.split(/[\s,;]+/).map((part) => part.trim()).filter(Boolean);
  const invalid: string[] = [];
  const seen = new Set<number>();
  const ports: number[] = [];
  for (const token of tokens) {
    if (!/^\d+$/.test(token)) {
      invalid.push(token);
      continue;
    }
    const port = Number(token);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      invalid.push(token);
      continue;
    }
    if (seen.has(port)) {
      continue;
    }
    seen.add(port);
    ports.push(port);
  }
  ports.sort((left, right) => left - right);
  return {
    ports,
    error: invalid.length ? `Invalid port${invalid.length === 1 ? "" : "s"}: ${invalid.join(", ")}.` : "",
  };
}

function parseQuickValidatorEndpoints(host: string, ports: string, sni: string): ValidatorEndpointInput[] {
  const normalizedHost = host.trim();
  if (!normalizedHost) {
    throw new Error("Host is required.");
  }
  const portValues = ports.trim()
    ? ports
      .split(/[\s,]+/)
      .map((value) => value.trim())
      .filter(Boolean)
    : [];
  const parsedPorts = portValues.length
    ? portValues.map((value) => parseValidatorPort(value, normalizedHost))
    : [defaultValidatorPort];
  return parsedPorts.map((port) => validatorEndpoint(normalizedHost, port, sni));
}

function parseValidatorPort(value: string, host: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Endpoint ${host} has invalid port ${value}.`);
  }
  return port;
}

function validatorEndpoint(host: string, port: number, sni: string): ValidatorEndpointInput {
  const normalizedHost = host.trim().replace(/\.$/, "");
  if (!normalizedHost) {
    throw new Error("Endpoint host is required.");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Endpoint ${normalizedHost} has invalid port ${port}.`);
  }
  return { host: normalizedHost, port, sni: sni.trim() || undefined };
}

function validatorStatusDot(status: string, paused = false): string {
  if (status === "running" && paused) {
    return "disconnected";
  }
  switch (status) {
    case "running":
      return "connecting";
    case "completed":
      return "connected";
    case "failed":
      return "failed";
    default:
      return "disconnected";
  }
}

function validatorStatusLabel(status: string, paused = false): string {
  if (status === "running" && paused) {
    return "Validator paused";
  }
  switch (status) {
    case "running":
      return "Validator running";
    case "completed":
      return "Scan complete";
    case "cancelled":
      return "Scan cancelled";
    case "failed":
      return "Scan failed";
    default:
      return "Validator idle";
  }
}

function messageFromError(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (typeof err === "string") {
    return err;
  }
  return "Operation failed";
}

export default App;

function LegacyImportDialog({
  offer,
  onImport,
  onDismiss,
}: {
  offer: LegacyImportOffer | null;
  onImport: () => void;
  onDismiss: () => void;
}) {
  if (!offer) {
    return null;
  }

  const found = [
    offer.profiles > 0 ? `${offer.profiles} profile${offer.profiles === 1 ? "" : "s"}` : "",
    offer.subscriptions > 0 ? `${offer.subscriptions} subscription${offer.subscriptions === 1 ? "" : "s"}` : "",
    offer.frontingIps > 0 ? `${offer.frontingIps} fronting IP${offer.frontingIps === 1 ? "" : "s"}` : "",
  ].filter(Boolean);

  return (
    <Dialog open onOpenChange={(open) => !open && onDismiss()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Bring your profiles over?</DialogTitle>
          <DialogDescription>
            WhiteDNS Desktop is installed and has {found.join(", ")} saved. They can be copied into
            WhiteVPN Desktop now. Nothing in WhiteDNS Desktop is changed or removed.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onDismiss}>
            Not now
          </Button>
          <Button onClick={onImport}>Import</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}



// The first-run gate, as WhiteVPN for Android has it.
//
// Acceptance is versioned: when the policy changes the version goes up and this
// comes back, which is the only way an acceptance says anything about what was
// agreed to. There is no "later" — the app refuses to connect until this is
// answered, in the backend as well as here — so the other way out is to quit.
function PrivacyPolicyGate({ onAccept, onQuit, t }: { onAccept: () => void; onQuit: () => void; t: TranslateFn }) {
  const points: StringKey[] = [
    "privacy.local",
    "privacy.catalogue",
    "privacy.checks",
    "privacy.traffic",
    "privacy.noAnalytics",
  ];
  return (
    <Dialog open>
      <DialogContent className="sm:max-w-lg" showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t("privacy.title")}</DialogTitle>
          <DialogDescription>{t("privacy.intro")}</DialogDescription>
        </DialogHeader>
        <ul className="grid gap-2 text-sm">
          {points.map((key) => (
            <li key={key} className="flex gap-2">
              <Check className="mt-0.5 size-4 shrink-0 text-emerald-600" />
              <span>{t(key)}</span>
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">
          {t("privacy.more")}{" "}
          <button type="button" className="underline underline-offset-2" onClick={() => openExternalUrl(whiteDnsTelegramUrl)}>
            {whiteDnsTelegramUrl}
          </button>
        </p>
        <DialogFooter>
          <Button variant="outline" onClick={onQuit}>
            {t("privacy.quit")}
          </Button>
          <Button onClick={onAccept}>{t("privacy.accept")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// The settings WhiteVPN for Android exposes, in the order it shows them, so
// that someone arriving from the phone recognises the screen.
//
// Built from the components the rest of the app already uses: PageShell for the
// header, a Card per section, and the same bordered switch row the VPN page uses
// for its controls. Nothing new is introduced for the sake of these settings.
function WhiteVPNSettingsPage({
  state,
  onState,
  onError,
  onSuccess,
  onNavigate,
  t,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  onNavigate: (page: Page) => void;
  t: TranslateFn;
}) {
  const stored = state.whiteVpn;
  const [draft, setDraft] = useState<WhiteVPNSettings>(stored);
  const [frontingDraft, setFrontingDraft] = useState("");
  const [processDraft, setProcessDraft] = useState("");
  const [saving, setSaving] = useState(false);

  // Settings changed elsewhere — a backup restore, most likely — have to reach
  // this form, or it would go on showing, and then saving, what it loaded with.
  useEffect(() => {
    setDraft(stored);
  }, [stored]);

  const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(stored), [draft, stored]);

  async function save(next: WhiteVPNSettings) {
    setSaving(true);
    try {
      onState(await backend.saveWhiteVpnSettings(next));
      onSuccess(t("settings.saved"));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSaving(false);
    }
  }

  function patch(changes: Partial<WhiteVPNSettings>) {
    setDraft((current) => ({ ...current, ...changes }));
  }

  function addFrontingIP() {
    const value = frontingDraft.trim();
    if (!value) {
      return;
    }
    if (draft.frontingIps.includes(value)) {
      setFrontingDraft("");
      return;
    }
    if (draft.frontingIps.length >= maxFrontingIPs) {
      onError(t("settings.fronting.tooMany", { max: maxFrontingIPs }));
      return;
    }
    patch({ frontingIps: [...draft.frontingIps, value] });
    setFrontingDraft("");
  }

  function addProcess() {
    const value = processDraft.trim();
    if (!value) {
      return;
    }
    if (draft.splitTunnel.processes.includes(value)) {
      setProcessDraft("");
      return;
    }
    patch({ splitTunnel: { ...draft.splitTunnel, processes: [...draft.splitTunnel.processes, value] } });
    setProcessDraft("");
  }

  const dnsMode = draft.dnsPrivacy.mode;

  return (
    <PageShell
      eyebrow="WhiteVPN"
      title={t("settings.title")}
      actions={
        <>
          <Button variant="outline" onClick={() => setDraft(stored)} disabled={!dirty || saving}>
            {t("settings.discard")}
          </Button>
          <Button onClick={() => void save(draft)} disabled={!dirty || saving}>
            <Save />
            {t("settings.save")}
          </Button>
        </>
      }
    >
      <SettingsSection title={t("settings.connection.title")} description={t("settings.connection.description")}>
        <div className="grid gap-2 sm:grid-cols-2">
          <SettingSwitchRow
            label={t("settings.tunnel")}
            checked={draft.tunEnabled}
            onCheckedChange={(checked) => patch({ tunEnabled: checked })}
          />
          <SettingSwitchRow
            label={t("settings.killSwitch")}
            checked={draft.killSwitch.enabled}
            disabled
            onCheckedChange={(checked) => patch({ killSwitch: { enabled: checked } })}
          />
        </div>
        <FieldDescription>{t("settings.tunnel.description")}</FieldDescription>
        <FieldDescription>{t("settings.killSwitch.description")}</FieldDescription>
      </SettingsSection>

      <SettingsSection title={t("settings.security.title")} description={t("settings.security.description")}>
        <div className="grid gap-2 sm:grid-cols-2">
          <SettingSwitchRow
            label={t("settings.tlsIntegrity")}
            checked={draft.tlsIntegrityEnabled}
            onCheckedChange={(checked) => patch({ tlsIntegrityEnabled: checked })}
          />
        </div>
        <FieldDescription>{t("settings.tlsIntegrity.description")}</FieldDescription>
      </SettingsSection>

      <SettingsSection title={t("settings.dns.title")} description={t("settings.dns.description")}>
        <FieldGroup className="grid gap-4 md:grid-cols-3">
          <Field>
            <FieldLabel>{t("settings.dns.mode")}</FieldLabel>
            <Select
              value={dnsMode}
              onValueChange={(value) =>
                patch({ dnsPrivacy: { ...draft.dnsPrivacy, mode: value as DNSPrivacyMode } })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="automatic">{t("settings.dns.automatic")}</SelectItem>
                <SelectItem value="doh">{t("settings.dns.doh")}</SelectItem>
                <SelectItem value="dot">{t("settings.dns.dot")}</SelectItem>
              </SelectContent>
            </Select>
            <FieldDescription>{t("settings.dns.hint")}</FieldDescription>
          </Field>
          <TextField
            label={t("settings.dns.dohServer")}
            value={draft.dnsPrivacy.dohUrl}
            placeholder="https://1.1.1.1/dns-query"
            disabled={dnsMode !== "doh"}
            onChange={(value) => patch({ dnsPrivacy: { ...draft.dnsPrivacy, dohUrl: value } })}
          />
          <TextField
            label={t("settings.dns.dotServer")}
            value={draft.dnsPrivacy.dotEndpoint}
            placeholder="tls://1.1.1.1:853"
            disabled={dnsMode !== "dot"}
            onChange={(value) => patch({ dnsPrivacy: { ...draft.dnsPrivacy, dotEndpoint: value } })}
          />
        </FieldGroup>
      </SettingsSection>

      <SettingsSection
        title={t("settings.fronting.title")}
        description={t("settings.fronting.description", { max: maxFrontingIPs })}
      >
        <div className="flex flex-wrap gap-2">
          <Input
            value={frontingDraft}
            placeholder="1.2.3.4 or 1.2.3.4:443"
            className="max-w-xs"
            onChange={(event) => setFrontingDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                addFrontingIP();
              }
            }}
          />
          <Button variant="outline" onClick={addFrontingIP} disabled={draft.frontingIps.length >= maxFrontingIPs}>
            {t("common.add")}
          </Button>
        </div>
        <RemovableBadges
          values={draft.frontingIps}
          emptyLabel={t("settings.fronting.empty")}
          onRemove={(value) => patch({ frontingIps: draft.frontingIps.filter((entry) => entry !== value) })}
        />
      </SettingsSection>

      <SettingsSection title={t("settings.splitTunnel.title")} description={t("settings.splitTunnel.description")}>
        <FieldGroup className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel>{t("settings.splitTunnel.mode")}</FieldLabel>
            <Select
              value={draft.splitTunnel.mode}
              onValueChange={(value) =>
                patch({ splitTunnel: { ...draft.splitTunnel, mode: value as SplitTunnelMode } })
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="off">{t("settings.splitTunnel.off")}</SelectItem>
                <SelectItem value="bypass_selected">{t("settings.splitTunnel.bypass")}</SelectItem>
                <SelectItem value="vpn_only_selected">{t("settings.splitTunnel.vpnOnly")}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel>{t("settings.splitTunnel.program")}</FieldLabel>
            <div className="flex gap-2">
              <Input
                value={processDraft}
                placeholder="firefox.exe"
                disabled={draft.splitTunnel.mode === "off"}
                onChange={(event) => setProcessDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    addProcess();
                  }
                }}
              />
              <Button variant="outline" onClick={addProcess} disabled={draft.splitTunnel.mode === "off"}>
                {t("common.add")}
              </Button>
            </div>
            <FieldDescription>{t("settings.splitTunnel.programHint")}</FieldDescription>
          </Field>
        </FieldGroup>
        <RemovableBadges
          values={draft.splitTunnel.processes}
          emptyLabel={t("settings.splitTunnel.empty")}
          onRemove={(value) =>
            patch({
              splitTunnel: {
                ...draft.splitTunnel,
                processes: draft.splitTunnel.processes.filter((entry) => entry !== value),
              },
            })
          }
        />
      </SettingsSection>

      <SettingsSection title={t("settings.noise.title")} description={t("settings.noise.description")}>
        <div className="grid gap-2 sm:grid-cols-2">
          <SettingSwitchRow
            label={t("settings.noise.enable")}
            checked={draft.amneziaNoise.enabled}
            onCheckedChange={(checked) => patch({ amneziaNoise: { ...draft.amneziaNoise, enabled: checked } })}
          />
        </div>
        <FieldGroup className="grid gap-4 md:grid-cols-3">
          <NumberField
            label={t("settings.noise.count")}
            value={draft.amneziaNoise.count}
            min={minNoiseCount}
            max={maxNoiseCount}
            disabled={!draft.amneziaNoise.enabled}
            onChange={(value) => patch({ amneziaNoise: { ...draft.amneziaNoise, count: value } })}
          />
          <NumberField
            label={t("settings.noise.minSize")}
            value={draft.amneziaNoise.minSize}
            min={minNoiseSize}
            max={maxNoiseSize}
            disabled={!draft.amneziaNoise.enabled}
            onChange={(value) => patch({ amneziaNoise: { ...draft.amneziaNoise, minSize: value } })}
          />
          <NumberField
            label={t("settings.noise.maxSize")}
            value={draft.amneziaNoise.maxSize}
            min={minNoiseSize}
            max={maxNoiseSize}
            disabled={!draft.amneziaNoise.enabled}
            onChange={(value) => patch({ amneziaNoise: { ...draft.amneziaNoise, maxSize: value } })}
          />
        </FieldGroup>
      </SettingsSection>

      <SettingsSection
        title={t("settings.appearance.title")}
        description={t("settings.appearance.description")}
      >
        <FieldGroup className="grid gap-4 md:grid-cols-2">
          <Field>
            <FieldLabel>{t("settings.language")}</FieldLabel>
            <Select
              value={normalizeLanguage(draft.language)}
              onValueChange={(value) => patch({ language: value })}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {languages.map((entry) => (
                  <SelectItem key={entry.value} value={entry.value}>
                    {entry.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldDescription>{t("settings.language.hint")}</FieldDescription>
          </Field>
        </FieldGroup>
      </SettingsSection>

      <Card>
        <CardHeader>
          <CardTitle>{t("settings.engine.title")}</CardTitle>
          <CardDescription>{t("settings.engine.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" onClick={() => onNavigate("engine-settings")}>
            <Settings />
            {t("settings.engine.open")}
          </Button>
        </CardContent>
      </Card>
    </PageShell>
  );
}

function SettingsSection({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">{children}</CardContent>
    </Card>
  );
}

// The same bordered row the VPN page uses for its controls, so a switch looks
// and behaves the same wherever it appears.
function SettingSwitchRow({
  label,
  checked,
  disabled,
  onCheckedChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex h-9 items-center justify-between gap-3 rounded-md border bg-background px-2.5 text-xs font-medium">
      <span>{label}</span>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onCheckedChange} aria-label={label} />
    </label>
  );
}

function RemovableBadges({
  values,
  emptyLabel,
  onRemove,
}: {
  values: string[];
  emptyLabel: string;
  onRemove: (value: string) => void;
}) {
  if (values.length === 0) {
    return <p className="text-xs text-muted-foreground">{emptyLabel}</p>;
  }
  return (
    <div className="flex flex-wrap gap-2">
      {values.map((value) => (
        <Badge key={value} variant="secondary" className="gap-1 font-mono text-xs">
          {value}
          <button
            type="button"
            className="ms-1 rounded-sm opacity-70 transition-opacity hover:opacity-100"
            onClick={() => onRemove(value)}
            aria-label={"Remove " + value}
          >
            <X className="size-3" />
          </button>
        </Badge>
      ))}
    </div>
  );
}
