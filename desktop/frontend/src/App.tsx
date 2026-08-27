import {
  Activity,
  AlertCircle,
  ArrowUpCircle,
  Check,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Globe,
  Copy,
  Cpu,
  Download,
  Eye,
  EyeOff,
  ExternalLink,
  FileText,
  Gauge,
  ListChecks,
  Monitor,
  Moon,
  Pause,
  Pencil,
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
  Youtube,
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
import { Button, buttonVariants } from "@/components/ui/button";
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
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
  UpdateStatus,
  WhiteVPNNode,
  NodeMeasurement,
  WhiteVPNNodeList,
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

type Page = "vpn" | "servers" | "subscriptions" | "settings" | "logs" | "white-ips" | "validator" | "backup";
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
const whiteDnsYoutubeUrl = "https://www.youtube.com/@WhiteDNS?sub_confirmation=1";
// Mirrors the limits in internal/model/whitevpn_settings.go. Values outside them
// are repaired on save, so these only decide when a control stops accepting more.
const maxFrontingIPs = 5;
const minNoiseCount = 1;
const maxNoiseCount = 20;
const minNoiseSize = 1;
const maxNoiseSize = 1280;
const whiteDNSVPNSubscriptionID = "whitedns-vpn";
const manualServerSourceID = "manual";
const manualConfigLinkPattern = /\b(?:vless|vmess|trojan|ss|shadowsocks|hysteria|hysteria2|hy2|wireguard|wg):\/\/\S+/i;

function looksLikeManualConfig(text: string): boolean {
  return manualConfigLinkPattern.test(text) || (text.includes("[Interface]") && text.includes("[Peer]"));
}

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
    systemProxy: Boolean(runtime.systemProxy),
    systemProxyStranded: Boolean(runtime.systemProxyStranded),
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
    allowInsecureTls: Boolean(subscription.allowInsecureTls),
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

// The three ways traffic can reach the engine, as one value.
//
// The tunnel takes precedence because that is what the connect path does: with
// it on, the system proxy is deliberately left alone.
type RoutingMode = "tun" | "systemProxy" | "proxyOnly";

function routingMode(settings: WhiteVPNSettings): RoutingMode {
  if (settings.tunEnabled) {
    return "tun";
  }
  return settings.setSystemProxy ? "systemProxy" : "proxyOnly";
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
  // Where the engine's proxy listens, asked once. The page has to be able to
  // name it while disconnected — that is when someone is setting a browser up.
  const [engineProxyEndpoint, setEngineProxyEndpoint] = useState("");
  const [appVersion, setAppVersion] = useState("");
  // What the app knows about newer releases. Null until the check has run, and
  // a check that could not reach GitHub leaves available false rather than
  // saying anything — it is blocked in the places this app is used, and a
  // failed check must not become a message.
  const [update, setUpdate] = useState<UpdateStatus | null>(null);
  const [page, setPage] = useState<Page>("vpn");
  const [errorToast, setErrorToast] = useState<AppErrorToast | null>(null);
  const [successToast, setSuccessToast] = useState<AppErrorToast | null>(null);
  const [validatorState, setValidatorState] = useState<ValidatorState>(defaultValidatorState);
  // The nodes the Servers page is looking at, and which subscription they came
  // from. The dashboard always shows the selected subscription; Servers may be
  // browsing another, which is the whole point of the picker there.
  const [nodes, setNodes] = useState<WhiteVPNNode[]>([]);
  const [browsing, setBrowsing] = useState("");
  const [nodesLoading, setNodesLoading] = useState(false);
  const [nodeTestRunning, setNodeTestRunning] = useState(false);
  const runtimeLogBufferRef = useRef<RuntimeLogEntry[]>([]);
  const runtimeLogFlushTimerRef = useRef<number | null>(null);

  // Which subscription the Servers page is showing: the one the user picked
  // there, or the connected one until they pick. A pick that no longer exists
  // falls back rather than leaving the page pointed at nothing.
  const browsedSubscriptionId = useMemo(() => {
    const fallback = state?.selectedSubscriptionId || whiteDNSVPNSubscriptionID;
    if (!browsing) {
      return fallback;
    }
    const manualAvailable = browsing === manualServerSourceID && (state?.v2rayProfiles ?? []).some((profile) => !profile.subscriptionId);
    return manualAvailable || (state?.v2raySubscriptions ?? []).some((subscription) => subscription.id === browsing) ? browsing : fallback;
  }, [browsing, state?.selectedSubscriptionId, state?.v2rayProfiles, state?.v2raySubscriptions]);

  // The nodes:test handler is registered once and would otherwise close over
  // whichever subscription was showing when the page mounted.
  const browsedSubscriptionRef = useRef(browsedSubscriptionId);
  useEffect(() => {
    browsedSubscriptionRef.current = browsedSubscriptionId;
  }, [browsedSubscriptionId]);

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

  async function loadNodes(refresh: boolean, subscriptionId?: string) {
    const id = subscriptionId ?? browsedSubscriptionId;
    setNodesLoading(true);
    try {
      const list = await backend.listSubscriptionNodes(id, refresh);
      setBrowsing(id);
      setNodes(list.nodes || []);
    } catch (err) {
      // The list that came back is what could be read, which for a stale cache
      // is still worth showing next to the error.
      setBrowsing(id);
      setNodes([]);
      showError(messageFromError(err));
    } finally {
      setNodesLoading(false);
    }
  }

  async function importManualConfigs(rawText: string): Promise<number> {
    setNodesLoading(true);
    try {
      const result = await backend.importV2RayProfiles(rawText);
      applyState(result.state);
      const list = await backend.listSubscriptionNodes(manualServerSourceID, true);
      setBrowsing(manualServerSourceID);
      setNodes(list.nodes || []);
      return result.imported;
    } finally {
      setNodesLoading(false);
    }
  }

  async function runNodeTest(request: NodeTestRequest) {
    try {
      setNodeTestRunning(true);
      // The page's subscription is what a normal run measures. A run covering
      // everything supplies its own list per subscription, so naming one here
      // would only invite the question of which wins.
      await backend.startNodeTest(
        request.allSubscriptions ? request : { ...request, subscriptionId: browsedSubscriptionId },
      );
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
      let current = state;
      if (browsedSubscriptionId !== current.selectedSubscriptionId) {
        // The node is named in a list the app is not connecting through, so the
        // subscription moves with it. Otherwise the name would be checked
        // against the other list and refused.
        current = await backend.selectSubscription(browsedSubscriptionId);
        applyState(current);
      }
      applyState(await backend.saveWhiteVpnSelection(current.whiteVpn.countryCode, { ...current.whiteVpn.connection, node: name }));
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
      .getAppVersion()
      .then(setAppVersion)
      .catch(() => setAppVersion(""));
    backend
      .getLocalProxyEndpoint()
      .then(setEngineProxyEndpoint)
      .catch(() => setEngineProxyEndpoint(""));
    // Not on the critical path: nothing waits for it, and a slow or blocked
    // GitHub delays nothing. The backend caches for six hours, so this costs a
    // request on the first launch of a session and nothing after.
    backend
      .checkForUpdate(false)
      .then(setUpdate)
      .catch(() => setUpdate(null));
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
      // Connecting retries the subscriptions the network had been blocking, so
      // the rows showing that failure are stale the moment it succeeds.
      onRuntimeEvent<unknown>("subscriptions:changed", () => {
        void backend.getAppState().then(applyState);
      }),
      onRuntimeEvent<NodeMeasurement>("nodes:test", (measurement) => {
        // A run can cover every subscription now, so a result has to say which
        // list it is for. Node names come from providers and two subscriptions
        // can both hold a "Germany 01" — applied on the name alone, one list's
        // measurement would overwrite the other's wherever they collide.
        if (measurement.subscriptionId !== browsedSubscriptionRef.current) {
          return;
        }
        setNodes((current) =>
          current.map((entry) => (entry.name === measurement.node.name ? measurement.node : entry)),
        );
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
      // Something worth saying that is not a failure — a connection that came
      // up while something around it did not. It must not use showError, or a
      // working connection is reported as a broken one, which is the mistake
      // this event exists to undo.
      onRuntimeEvent<string>("runtime:notice", showSuccess),
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

  // The Servers page is useless without a catalogue, and it must be the
  // catalogue it says it is showing. Above the early return below, because it
  // is a hook and hooks cannot be conditional.
  useEffect(() => {
    if (page === "servers" && !nodesLoading && (!nodes.length || browsing !== browsedSubscriptionId)) {
      void loadNodes(false, browsedSubscriptionId);
    }
  }, [page, browsedSubscriptionId]);

  if (!state) {
    return (
      <>
        <LoadingView t={t} />
        <ErrorToast toast={errorToast} onDismiss={clearErrorToast} t={t} />
        <SuccessToast toast={successToast} onDismiss={clearSuccessToast} t={t} />
      </>
    );
  }

  const activePage = page;

  return (
    <TooltipProvider>
      <SidebarProvider defaultOpen>
        <AppSidebar page={activePage} runtime={state.runtime} onPage={setPage} language={language} version={appVersion} update={update} t={t} />
        <SidebarInset className="min-w-0 overflow-x-hidden">
          <main className="min-h-svh min-w-0 overflow-x-hidden bg-muted/30 p-4 md:p-6">
            <div className="mx-auto flex w-full min-w-0 max-w-7xl flex-col gap-4">
              <div className="flex items-center justify-between gap-2 md:hidden">
                <div className="flex min-w-0 items-center gap-2">
                  <SidebarTrigger />
                  <AppIcon className="size-7" />
                  <span className="min-w-0 truncate text-sm font-medium">WhiteVPN</span>
                </div>
                <ThemeSettingsMenu t={t} />
              </div>

              <ErrorToast toast={errorToast} onDismiss={clearErrorToast} t={t} />
              <SuccessToast toast={successToast} onDismiss={clearSuccessToast} t={t} />

              {activePage === "vpn" && (
                <WhiteDNSVPNPage
                  state={state}
                  proxyEndpoint={engineProxyEndpoint}
                  onState={applyState}
                  onError={showError}
                  onNavigate={setPage}
                  language={language}
                  t={t}
                />
              )}

              {activePage === "servers" && (
                <NodesPage
                  state={state}
                  nodes={nodes}
                  subscriptionId={browsedSubscriptionId}
                  onSelectSubscription={(id) => void loadNodes(false, id)}
                  loading={nodesLoading}
                  testing={nodeTestRunning}
                  onReload={() => void loadNodes(true)}
                  onRunTest={(request) => void runNodeTest(request)}
                  onCancelTest={() => void cancelNodeTest()}
                  onSelectNode={(name) => void useNode(name)}
                  onImportManual={importManualConfigs}
                  onNodesChanged={(list) => {
                    setNodes(list.nodes);
                    // Editing a config changes the stored profiles, which other
                    // pages read; refreshing the state keeps them in step.
                    void backend.getAppState().then(applyState);
                  }}
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

              {activePage === "logs" && (
                <LogsPage runtime={state.runtime} runtimeType="v2ray" onState={applyState} onError={showError} t={t} />
              )}

              {activePage === "white-ips" && (
                <V2RayWhiteIPsPage onState={applyState} onError={showError} onSuccess={showSuccess} t={t} />
              )}

              {activePage === "validator" && (
                <ValidatorPage
                  state={validatorState}
                  onState={applyValidatorState}
                  onAppState={applyState}
                  onError={showError}
                  t={t}
                />
              )}

              {activePage === "backup" && (
                <FullBackupPage state={state} onState={applyState} onError={showError} onSuccess={showSuccess} t={t} />
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

function ErrorToast({ toast, onDismiss, t }: { toast: AppErrorToast | null; onDismiss: () => void; t: TranslateFn }) {
  if (!toast) {
    return null;
  }

  return (
    <div className="fixed top-4 end-4 start-4 z-[100] sm:top-6 sm:end-6 sm:start-auto sm:w-full sm:max-w-md">
      <Alert variant="destructive" className="border-destructive/25 shadow-lg">
        <AlertCircle />
        <AlertTitle>{t("toast.failed")}</AlertTitle>
        <AlertDescription>{toast.message}</AlertDescription>
        <AlertAction>
          <Button variant="ghost" size="icon-sm" onClick={onDismiss} aria-label={t("common.dismiss")}>
            <X />
          </Button>
        </AlertAction>
      </Alert>
    </div>
  );
}

function SuccessToast({ toast, onDismiss, t }: { toast: AppErrorToast | null; onDismiss: () => void; t: TranslateFn }) {
  if (!toast) {
    return null;
  }

  return (
    <div className="fixed top-4 end-4 start-4 z-[100] sm:top-6 sm:end-6 sm:start-auto sm:w-full sm:max-w-md">
      <Alert className="border-emerald-200 bg-emerald-50 text-emerald-950 shadow-lg dark:border-emerald-900/60 dark:bg-emerald-950 dark:text-emerald-100">
        <CheckCircle2 />
        <AlertTitle>{toast.message}</AlertTitle>
        <AlertAction>
          <Button variant="ghost" size="icon-sm" onClick={onDismiss} aria-label={t("common.dismiss")}>
            <X />
          </Button>
        </AlertAction>
      </Alert>
    </div>
  );
}

function ThemeSettingsMenu({ className, sidebar = false, t }: { className?: string; sidebar?: boolean; t: TranslateFn }) {
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
        aria-label={t("theme.open")}
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
          aria-label={t("theme.title")}
          className="absolute end-0 top-[calc(100%+0.375rem)] z-50 w-52 overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <div className="flex items-center justify-between gap-2 px-2 py-1.5 text-sm font-medium">
            <span>{t("theme.title")}</span>
            <span className="rounded-sm bg-muted px-1.5 py-0.5 text-[0.65rem] font-normal uppercase leading-none text-muted-foreground">
              {resolvedTheme}
            </span>
          </div>
          <ThemeMenuItem
            icon={<Sun />}
            label={t("theme.light")}
            active={theme === "light"}
            onSelect={() => chooseTheme("light")}
          />
          <ThemeMenuItem
            icon={<Moon />}
            label={t("theme.dark")}
            active={theme === "dark"}
            onSelect={() => chooseTheme("dark")}
          />
          <ThemeMenuItem
            icon={<Monitor />}
            label={t("theme.system")}
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
  version,
  update,
  t,
}: {
  page: Page;
  runtime: RuntimeStatus;
  onPage: (page: Page) => void;
  language: Language;
  version: string;
  update: UpdateStatus | null;
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
              {/* Read from the binary, never typed here: a version in two
                  places is a version that will disagree with itself, and this
                  one shipped 1.0.1 while saying 1.0.0. Blank until it arrives,
                  because a stale number is worse than none. */}
              {update?.available ? (
                // The version becomes the way to the new one. Whoever is still
                // on an old build is not in the Telegram channel — that is who
                // this reaches — and the number they already glance at is the
                // right place to say so.
                <button
                  type="button"
                  onClick={() => openExternalUrl(update.url)}
                  className="flex items-center gap-1 truncate text-sm leading-normal text-primary hover:underline"
                  title={t("update.available", { version: update.latest })}
                >
                  <ArrowUpCircle className="size-3.5 shrink-0" />
                  <span className="truncate">{t("update.badge", { version: update.latest })}</span>
                </button>
              ) : (
                <p className="truncate text-sm leading-normal text-muted-foreground">{version ? `v${version}` : ""}</p>
              )}
            </div>
          </div>
          <ThemeSettingsMenu
            sidebar
            t={t}
            className="ms-auto group-data-[collapsible=icon]:hidden"
          />
        </div>
        <a
          href={whiteDnsTelegramUrl}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t("nav.source.open")}
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
      <a
        href={whiteDnsYoutubeUrl}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(event) => {
          event.preventDefault();
          openExternalUrl(whiteDnsYoutubeUrl);
        }}
        className="mx-2 flex min-h-11 w-auto items-center justify-center gap-2 rounded-lg bg-red-600 px-3 text-sm font-semibold whitespace-nowrap text-white hover:bg-red-700 focus-visible:ring-2 focus-visible:ring-foreground focus-visible:ring-offset-2 focus-visible:ring-offset-sidebar focus-visible:outline-none active:bg-red-800 group-data-[collapsible=icon]:hidden"
      >
        <Youtube className="size-5 shrink-0" aria-hidden="true" />
        <span>{t("nav.youtubeSubscribe")}</span>
      </a>
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

// Nothing ticked means everything, which is what the single-select "All" entry
// used to mean. Keeping that shape avoids a state where the list is empty
// because the user has narrowed it to nothing without noticing.
function toggleFilter(selected: string[], value: string): string[] {
  return selected.includes(value) ? selected.filter((entry) => entry !== value) : [...selected, value];
}

function filterSummary(selected: string[], all: string): string {
  if (selected.length === 0) {
    return all;
  }
  if (selected.length === 1) {
    return selected[0];
  }
  return `${selected.length}`;
}

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
  proxyEndpoint,
  onState,
  onError,
  onNavigate,
  language,
  t,
}: {
  state: AppState;
  proxyEndpoint: string;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onNavigate: (page: Page) => void;
  language: Language;
  t: TranslateFn;
}) {
  const runtime = state.runtime;
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
  // While connected, where it is actually listening; otherwise where it will
  // listen, which is a constant of the engine. Never the V2Ray settings
  // profile's port: nothing has read that since the Xray path was removed, and
  // it was showing a number no traffic would ever arrive on.
  const localProxyEndpoint = runtimeProxyDisplayEndpoint(runtime) || proxyEndpoint || "-";
  // Disabled only while stopping, as on the phone: every other state has
  // something for a click to do, including connecting, which it stops.
  const connectDisabled =
    connectState === "disconnecting" ||
    otherRuntimeActive ||
    (startsConnection && pending !== null);
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
    ...(connectState === "disconnect"
      ? [
          {
            label: t("vpn.exit.ip"),
            value:
              exitCountry?.measured && runtime.exitIp
                ? `${flagFromCountryCode(exitCountry.code)} ${runtime.exitIp}`
                : runtime.exitChecked
                  ? t("vpn.exit.notMeasured")
                  : `${t("vpn.exit.checking")}…`,
            icon: Globe,
          },
        ]
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
                    {/* Copyable, because in proxy-only mode this address is the
                        product: it is what gets typed into Telegram or a
                        browser extension, and retyping it by eye off a badge is
                        how a digit goes missing. */}
                    <Badge
                      asChild
                      variant="outline"
                      className="h-6 cursor-pointer gap-1 px-3 hover:bg-accent"
                    >
                      <button
                        type="button"
                        title={t("vpn.localProxy.copy")}
                        onClick={() => void navigator.clipboard?.writeText(localProxyEndpoint)}
                      >
                        <Monitor className="size-3" />
                        <span className="max-w-48 truncate font-mono">{localProxyEndpoint}</span>
                      </button>
                    </Badge>
                    <Badge variant="outline" className="h-6 gap-1 px-3">
                      <Shield className="size-3" />
                      <span className="font-mono">{connectedFrontingIP || t("vpn.frontingAuto")}</span>
                    </Badge>
                    {runtime.systemProxy && (
                      <Badge variant="outline" className="h-6 gap-1 px-3" title={t("vpn.systemProxy.hint")}>
                        <Globe className="size-3" />
                        {t("vpn.systemProxy")}
                      </Badge>
                    )}
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

      {/* Shown whatever the connection is doing, because this is not about the
          connection: the engine has stopped and the machine is still pointed at
          it, so nothing on this desktop can reach the internet. A user who is
          told only "Disconnected" has no reason to look for that. */}
      {runtime.systemProxyStranded && (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>{t("vpn.systemProxy.stranded")}</AlertTitle>
          <AlertDescription>{t("vpn.systemProxy.stranded.description")}</AlertDescription>
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
// The speed test asks Cloudflare for a file of a given size, so the size is the
// only part worth exposing. One megabyte is enough to rank nodes and is what the
// Android client settled on; the old ten-megabyte default cost a hundred times
// more traffic across a full run for no better ordering.
const speedTestURLPrefix = "https://speed.cloudflare.com/__down?bytes=";
const defaultSpeedTestMegabytes = 1;
const minSpeedTestMegabytes = 1;
const maxSpeedTestMegabytes = 100;
const bytesPerMegabyte = 1_000_000;

function speedTestURLFor(megabytes: number): string {
  const size = Math.min(Math.max(Math.round(megabytes), minSpeedTestMegabytes), maxSpeedTestMegabytes);
  return `${speedTestURLPrefix}${size * bytesPerMegabyte}`;
}

// A URL the field did not write - a custom target from an older build - reads
// back as the default rather than as a nonsense size.
function megabytesFromSpeedTestURL(url: string): number {
  if (!url.startsWith(speedTestURLPrefix)) {
    return defaultSpeedTestMegabytes;
  }
  const bytes = Number(url.slice(speedTestURLPrefix.length));
  if (!Number.isFinite(bytes) || bytes < bytesPerMegabyte) {
    return defaultSpeedTestMegabytes;
  }
  return Math.round(bytes / bytesPerMegabyte);
}

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
  speedUrl: speedTestURLFor(defaultSpeedTestMegabytes),
};

function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

function NodesPage({
  state,
  nodes,
  subscriptionId,
  onSelectSubscription,
  loading,
  testing,
  onReload,
  onRunTest,
  onCancelTest,
  onSelectNode,
  onImportManual,
  onNodesChanged,
  onError,
  onSuccess,
  language,
  t,
}: {
  state: AppState;
  nodes: WhiteVPNNode[];
  subscriptionId: string;
  onSelectSubscription: (id: string) => void;
  loading: boolean;
  testing: boolean;
  onReload: () => void;
  onRunTest: (request: NodeTestRequest) => void;
  onCancelTest: () => void;
  onSelectNode: (name: string) => void;
  onImportManual: (rawText: string) => Promise<number>;
  onNodesChanged: (list: WhiteVPNNodeList) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  language: Language;
  t: TranslateFn;
}) {
  const [search, setSearch] = useState("");
  const [selectedCountries, setSelectedCountries] = useState<string[]>([]);
  const [selectedProtocols, setSelectedProtocols] = useState<string[]>([]);
  const [sort, setSort] = useState<NodeSort | null>({ column: "label", direction: "asc" });
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [request, setRequest] = useState<NodeTestRequest>(defaultNodeTest);
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [shareNode, setShareNode] = useState<WhiteVPNNode | null>(null);
  const [exportOpen, setExportOpen] = useState(false);
  // Base64 of the whole list is what a subscription URL serves, and several
  // clients take it pasted straight in. Plain links are what everything takes,
  // so that is the default and this is the option.
  const [exportBase64, setExportBase64] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importing, setImporting] = useState(false);
  // The config the edit form is open on, and the rows a delete is waiting to be
  // confirmed for. Deleting configs is not undoable, so it asks first.
  const [editing, setEditing] = useState<V2RayProfile | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<WhiteVPNNode[] | null>(null);
  const [deletingBusy, setDeletingBusy] = useState(false);
  // Hidden nodes are kept out of the way rather than out of reach: this reveals
  // them so they can be put back, which is the only way back from hiding one.
  const [showHidden, setShowHidden] = useState(false);
  const [hidingBusy, setHidingBusy] = useState(false);
  const unknown = t("vpn.nodes.unknownCountry");
  const manualProfileCount = state.v2rayProfiles.filter((profile) => !profile.subscriptionId).length;
  // How many lists a run covering everything would walk: the subscriptions, and
  // the hand-added configs when there are any.
  const sourceCount = state.v2raySubscriptions.length + (manualProfileCount > 0 ? 1 : 0);

  useEffect(() => {
    setSort(subscriptionId === manualServerSourceID ? null : { column: "label", direction: "asc" });
  }, [subscriptionId]);

  const countries = useMemo(() => countryOptions(nodes, language, unknown), [nodes, language, unknown]);
  const protocols = useMemo(() => [...new Set(nodes.map((node) => node.type).filter(Boolean))].sort(), [nodes]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = nodes.filter((node) => {
      // A node the user hid is out of the way by default and reachable through
      // the toggle, because hiding has to be undoable from somewhere.
      if (node.hidden && !showHidden) {
        return false;
      }
      if (selectedCountries.length > 0 && !selectedCountries.includes(node.countryCode)) {
        return false;
      }
      if (selectedProtocols.length > 0 && !selectedProtocols.includes(node.type)) {
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

    if (!sort) {
      return filtered;
    }

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
  }, [nodes, search, selectedCountries, selectedProtocols, sort, language, unknown, showHidden]);

  const hiddenCount = useMemo(() => nodes.filter((node) => node.hidden).length, [nodes]);
  const selectedNames = useMemo(() => visible.filter((node) => selected.has(node.name)).map((node) => node.name), [visible, selected]);
  const targets = selectedNames.length ? selectedNames : visible.map((node) => node.name);

  function toggleSort(column: NodeSortColumn) {
    setSort((current) =>
      current?.column === column
        ? { column, direction: current.direction === "asc" ? "desc" : "asc" }
        : { column, direction: "asc" }
    );
  }

  const allVisibleSelected = visible.length > 0 && visible.every((node) => selected.has(node.name));
  const someVisibleSelected = visible.some((node) => selected.has(node.name));

  // Clearing removes only what is on screen, so a selection made under one
  // filter is not silently thrown away by unticking under another.
  function toggleSelectAll() {
    setSelected((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        visible.forEach((node) => next.delete(node.name));
      } else {
        visible.forEach((node) => next.add(node.name));
      }
      return next;
    });
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

  // Every subscription in turn. The backend walks them one at a time, so this
  // takes as long as running the same test on each page in sequence — which is
  // what it replaces.
  function runTestsEverywhere() {
    onError("");
    // Nothing is marked pending: the rows on screen are one list of several,
    // and marking them would show a spinner on nodes whose turn may not have
    // come yet.
    setPending(null);
    onRunTest({ ...request, nodes: [], allSubscriptions: true });
  }

  // What a bulk export covers: the selection when there is one, everything on
  // screen when there is not — the same rule the test buttons follow, so the
  // filters someone narrowed the list with carry over to this too.
  const exportNodes = useMemo(
    () => (selectedNames.length ? visible.filter((node) => selected.has(node.name)) : visible),
    [visible, selected, selectedNames],
  );
  const exportLinks = useMemo(() => exportNodes.map((node) => node.link).filter(Boolean), [exportNodes]);
  // A subscription served as a mihomo document has no share link per node, so
  // some rows cannot be exported. Counted and said, rather than a shorter list
  // than the one that was selected appearing with no explanation.
  const exportSkipped = exportNodes.length - exportLinks.length;
  const exportText = useMemo(() => {
    const plain = exportLinks.join("\n");
    if (!exportBase64 || !plain) {
      return plain;
    }
    // btoa is Latin-1; a node name can carry a flag emoji or Persian, both of
    // which are outside it. Encode the bytes, not the code points.
    return btoa(String.fromCharCode(...new TextEncoder().encode(plain)));
  }, [exportLinks, exportBase64]);
  const exportFilename = `whitevpn-${exportLinks.length}-configs${exportBase64 ? "-base64" : ""}.txt`;

  async function copyExport() {
    try {
      await navigator.clipboard?.writeText(exportText);
      onSuccess(t("servers.export.copied", { count: exportLinks.length }));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function copyLink(node: WhiteVPNNode) {
    try {
      await navigator.clipboard?.writeText(node.link);
      onSuccess(t("servers.copied"));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  // Only a config added by hand can be edited or removed here. One from the
  // catalogue or a subscription carries no profile, because it is a reading of
  // what a provider is serving and comes back unchanged at the next refresh —
  // a delete button on it would undo itself.
  const editableNodes = useMemo(() => visible.filter((node) => Boolean(node.profileId)), [visible]);
  const selectedEditable = useMemo(
    () => editableNodes.filter((node) => selected.has(node.name)),
    [editableNodes, selected]
  );
  // The mirror of that: a subscription's nodes cannot be deleted, only hidden.
  const selectedHideable = useMemo(
    () => visible.filter((node) => !node.profileId && !node.hidden && selected.has(node.name)),
    [visible, selected]
  );

  async function openEditor(node: WhiteVPNNode) {
    onError("");
    try {
      // Read the stored config rather than rebuilding one from the row: the row
      // holds what the parser made of the config, which is a subset. Editing
      // that and saving it back would silently drop everything the row does not
      // show.
      setEditing(await backend.manualNodeProfile(node.profileId));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function saveEdited() {
    if (!editing || saving) {
      return;
    }
    onError("");
    setSaving(true);
    try {
      onNodesChanged(await backend.saveManualNode(editing));
      setEditing(null);
      onSuccess(t("servers.edit.saved"));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSaving(false);
    }
  }

  async function deleteConfirmed() {
    if (!deleting?.length || deletingBusy) {
      return;
    }
    onError("");
    setDeletingBusy(true);
    try {
      const removed = deleting;
      onNodesChanged(await backend.deleteManualNodes(removed.map((node) => node.profileId)));
      // A row that no longer exists must not stay selected, or the next test
      // runs against a node that is gone.
      setSelected((current) => {
        const next = new Set(current);
        removed.forEach((node) => next.delete(node.name));
        return next;
      });
      setDeleting(null);
      onSuccess(t("servers.delete.done", { count: removed.length }));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setDeletingBusy(false);
    }
  }

  // A subscription's nodes belong to whoever serves them: a refresh rebuilds
  // them all, so editing one is not something that could work. Copying takes it
  // into the user's own configs, where it is theirs and the edit form applies.
  async function copyToManual(node: WhiteVPNNode) {
    onError("");
    try {
      await backend.copyNodeToManual(subscriptionId, node.name);
      onSuccess(t("servers.copyToManual.done", { name: node.label }));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function setHidden(targets: WhiteVPNNode[], hidden: boolean) {
    if (!targets.length || hidingBusy) {
      return;
    }
    onError("");
    setHidingBusy(true);
    try {
      onNodesChanged(await backend.setNodesHidden(subscriptionId, targets.map((node) => node.name), hidden));
      onSuccess(hidden ? t("servers.hide.done", { count: targets.length }) : t("servers.unhide.done", { count: targets.length }));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setHidingBusy(false);
    }
  }

  async function importConfigs(rawText = importText) {
    if (!rawText.trim() || importing) {
      return;
    }
    onError("");
    setImporting(true);
    try {
      const count = await onImportManual(rawText);
      setImportText("");
      setImportOpen(false);
      setSort(null);
      onSuccess(t("servers.import.success", { count }));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setImporting(false);
    }
  }

  useEffect(() => {
    function handlePaste(event: ClipboardEvent) {
      const target = event.target;
      if (
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        (target instanceof HTMLElement && target.isContentEditable)
      ) {
        return;
      }
      const text = event.clipboardData?.getData("text") ?? "";
      if (!looksLikeManualConfig(text) || importing) {
        return;
      }
      event.preventDefault();
      void importConfigs(text);
    }

    window.addEventListener("paste", handlePaste);
    return () => window.removeEventListener("paste", handlePaste);
  }, [importing, onImportManual, onError, onSuccess, t]);

  // The page names the list it is showing, which is not always the one the VPN
  // connects through — a subscription just added has to be browsable before it
  // is chosen, or there is no way to look at it before committing to it.
  const inUse = subscriptionId === state.selectedSubscriptionId;
  // Connecting through a node in another subscription moves the selection with
  // it, and the selection cannot move while a tunnel built from the old one is
  // still up. Say so on the button rather than letting the click fail.
  const blockedByConnection = !inUse && profileSelectionLocked(state.runtime);

  return (
    <PageShell
      eyebrow="WhiteVPN"
      title={t("nav.servers")}
      actions={
        <>
          <Button variant="outline" onClick={() => setImportOpen(true)} disabled={importing}>
            <Upload />
            {t("servers.import")}
          </Button>
          {selectedEditable.length > 0 && (
            <Button variant="outline" className="text-destructive" onClick={() => setDeleting(selectedEditable)}>
              <Trash2 />
              {t("servers.deleteSelected", { count: selectedEditable.length })}
            </Button>
          )}
          {selectedHideable.length > 0 && (
            <Button variant="outline" onClick={() => void setHidden(selectedHideable, true)} disabled={hidingBusy}>
              <EyeOff />
              {t("servers.hideSelected", { count: selectedHideable.length })}
            </Button>
          )}
          {exportLinks.length > 0 && (
            <Button variant="outline" onClick={() => setExportOpen(true)}>
              <Download />
              {selectedNames.length
                ? t("servers.exportSelected", { count: exportLinks.length })
                : t("servers.exportAll", { count: exportLinks.length })}
            </Button>
          )}
          {hiddenCount > 0 && (
            <Button variant="outline" onClick={() => setShowHidden((shown) => !shown)}>
              {showHidden ? <EyeOff /> : <Eye />}
              {showHidden ? t("servers.hideHidden") : t("servers.showHidden", { count: hiddenCount })}
            </Button>
          )}
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
            <>
              <Button onClick={runTests} disabled={!visible.length}>
                <Gauge />
                {selectedNames.length ? t("servers.testSelected") : t("servers.testAll")}
              </Button>
              {/* Only when there is more than one list to cover. On a single
                  subscription this would be the button beside it, worded
                  differently. */}
              {sourceCount > 1 && (
                <Button variant="outline" onClick={runTestsEverywhere} title={t("servers.testEverywhere.hint")}>
                  <Gauge />
                  {t("servers.testEverywhere", { count: sourceCount })}
                </Button>
              )}
            </>
          )}
        </>
      }
    >
      <Card>
        <CardHeader className="p-3 pb-2">
          <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
            <Shield className="size-4" />
            <Select value={subscriptionId} onValueChange={onSelectSubscription} disabled={loading || testing}>
              <SelectTrigger className="h-8 w-56" aria-label={t("servers.category")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {manualProfileCount > 0 && (
                  <SelectItem value={manualServerSourceID}>
                    {t("servers.manual")} ({manualProfileCount})
                  </SelectItem>
                )}
                {state.v2raySubscriptions.map((subscription) => (
                  <SelectItem key={subscription.id} value={subscription.id}>
                    {subscription.name || t("nav.subscriptions")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {inUse ? (
              <Badge variant="secondary">{t("subs.inUse")}</Badge>
            ) : (
              <Badge variant="outline" className="text-amber-600 dark:text-amber-400" title={t("servers.notInUse.hint")}>
                {t("servers.notInUse")}
              </Badge>
            )}
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
            <DropdownMenu>
              <DropdownMenuTrigger
                className={cn(buttonVariants({ variant: "outline" }), "w-44 justify-between font-normal")}
              >
                <span className="truncate">
                  {t("vpn.location")}: {filterSummary(selectedCountries, t("vpn.types.all"))}
                </span>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="max-h-72 w-56 overflow-y-auto">
                {countries.map((entry) => (
                  <DropdownMenuCheckboxItem
                    key={entry.code}
                    checked={selectedCountries.includes(entry.code)}
                    onCheckedChange={() => setSelectedCountries(toggleFilter(selectedCountries, entry.code))}
                    onSelect={(event) => event.preventDefault()}
                  >
                    {flagFromCountryCode(entry.code)} {entry.name} ({entry.count})
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
            <DropdownMenu>
              <DropdownMenuTrigger
                className={cn(buttonVariants({ variant: "outline" }), "w-40 justify-between font-normal")}
              >
                <span className="truncate">
                  {t("vpn.types")}: {filterSummary(selectedProtocols, t("vpn.types.all"))}
                </span>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="max-h-72 w-48 overflow-y-auto">
                {protocols.map((type) => (
                  <DropdownMenuCheckboxItem
                    key={type}
                    checked={selectedProtocols.includes(type)}
                    onCheckedChange={() => setSelectedProtocols(toggleFilter(selectedProtocols, type))}
                    onSelect={(event) => event.preventDefault()}
                  >
                    {type}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
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
              <NumberField
                label={t("servers.option.speedSize")}
                value={megabytesFromSpeedTestURL(request.speedUrl)}
                min={minSpeedTestMegabytes}
                max={maxSpeedTestMegabytes}
                onChange={(value) => setRequest({ ...request, speedUrl: speedTestURLFor(value) })}
              />
              <FieldDescription className="md:col-span-3">{t("servers.option.hint")}</FieldDescription>
            </FieldGroup>
          )}
        </CardContent>
      </Card>

      <Card className="min-h-0">
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100svh-24rem)]">
            <table className="w-full min-w-[980px] table-fixed text-start text-sm">
              <thead className="sticky top-0 z-10 bg-muted/95 text-xs uppercase text-muted-foreground backdrop-blur">
                <tr>
                  <th className="w-10 px-2 py-2">
                    <input
                      type="checkbox"
                      className="size-4"
                      // Only what is on screen. Selecting behind an active
                      // filter would hand a test or a delete rows the user
                      // cannot see.
                      checked={allVisibleSelected}
                      ref={(element) => {
                        if (element) {
                          element.indeterminate = someVisibleSelected && !allVisibleSelected;
                        }
                      }}
                      onChange={toggleSelectAll}
                      disabled={!visible.length}
                      aria-label={t("servers.selectAll")}
                    />
                  </th>
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
                  {/* Wide enough for five 28px buttons and the gaps between
                      them. It was w-24 when a row had two, and adding edit and
                      delete pushed them out over the Speed column instead of
                      making the column bigger. */}
                  <th className="w-44 px-2 py-2 text-end font-medium">{t("servers.column.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((node) => (
                  <tr
                    key={node.name}
                    className={cn(
                      "border-b last:border-b-0 hover:bg-muted/40",
                      // Only ever on screen while hidden nodes are being shown,
                      // and it has to look different from the rest or there is
                      // no telling which ones they are.
                      node.hidden && "opacity-50"
                    )}
                  >
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
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              onClick={() => onSelectNode(node.name)}
                              disabled={blockedByConnection}
                              aria-label={t("servers.use")}
                            >
                              <Play />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{blockedByConnection ? t("subs.disconnectFirst") : t("servers.use")}</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              onClick={() => setShareNode(node)}
                              // A node read out of a provider's own
                              // configuration has no share link to give: the
                              // document carried settings, not a URL.
                              disabled={!node.link}
                              aria-label={t("servers.share")}
                            >
                              <Share2 />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{node.link ? t("servers.share") : t("servers.share.none")}</TooltipContent>
                        </Tooltip>
                        {/* A subscription's node cannot be edited — a refresh
                            rebuilds it — so it gets the two things that do
                            work: take a copy, or put it out of the way. */}
                        {!node.profileId && (
                          <>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  onClick={() => void copyToManual(node)}
                                  disabled={!node.link}
                                  aria-label={t("servers.copyToManual")}
                                >
                                  <Copy />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>
                                {node.link ? t("servers.copyToManual") : t("servers.copyToManual.none")}
                              </TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  className={cn(!node.hidden && "text-destructive hover:text-destructive")}
                                  onClick={() => void setHidden([node], !node.hidden)}
                                  disabled={hidingBusy}
                                  aria-label={node.hidden ? t("servers.unhide") : t("servers.hide")}
                                >
                                  {node.hidden ? <Eye /> : <EyeOff />}
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>{node.hidden ? t("servers.unhide") : t("servers.hide")}</TooltipContent>
                            </Tooltip>
                          </>
                        )}
                        {/* Offered only where there is a stored config behind
                            the row. See editableNodes. */}
                        {node.profileId && (
                          <>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  onClick={() => void openEditor(node)}
                                  aria-label={t("servers.edit")}
                                >
                                  <Pencil />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>{t("servers.edit")}</TooltipContent>
                            </Tooltip>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  className="text-destructive hover:text-destructive"
                                  onClick={() => setDeleting([node])}
                                  aria-label={t("servers.delete")}
                                >
                                  <Trash2 />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>{t("servers.delete")}</TooltipContent>
                            </Tooltip>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {!visible.length && (
                  <tr>
                    <td colSpan={9} className="px-3 py-10 text-center text-sm text-muted-foreground">
                      {/* An empty subscription and a filter that matches nothing
                          are different problems, and only one of them is the
                          user's own doing. */}
                      {loading ? t("vpn.nodes.loading") : nodes.length ? t("vpn.nodes.none") : t("servers.empty")}
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

      <Dialog open={Boolean(editing)} onOpenChange={(open) => !open && !saving && setEditing(null)}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>{t("servers.edit.title")}</DialogTitle>
            <DialogDescription>{t("servers.edit.description")}</DialogDescription>
          </DialogHeader>
          <ScrollArea className="max-h-[60svh] pe-3">
            {editing && <ManualNodeForm profile={editing} onChange={setEditing} t={t} />}
          </ScrollArea>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)} disabled={saving}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => void saveEdited()} disabled={saving || !editing?.server.trim()}>
              {saving ? t("servers.edit.saving") : t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleting)} onOpenChange={(open) => !open && !deletingBusy && setDeleting(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("servers.delete.title")}</DialogTitle>
            {/* Named rather than counted where there is one, because "delete 1
                config" is not enough to check against before it is gone. */}
            <DialogDescription>
              {deleting?.length === 1
                ? t("servers.delete.one", { name: deleting[0].label })
                : t("servers.delete.many", { count: deleting?.length ?? 0 })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleting(null)} disabled={deletingBusy}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={() => void deleteConfirmed()} disabled={deletingBusy}>
              <Trash2 />
              {deletingBusy ? t("servers.delete.deleting") : t("servers.delete")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={importOpen} onOpenChange={(open) => !importing && setImportOpen(open)}>
        <DialogContent className="sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{t("servers.import.title")}</DialogTitle>
            <DialogDescription>{t("servers.import.description")}</DialogDescription>
          </DialogHeader>
          <Textarea
            dir="ltr"
            value={importText}
            onChange={(event) => setImportText(event.target.value)}
            placeholder={t("servers.import.placeholder")}
            className="h-56 min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
            autoFocus
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)} disabled={importing}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => void importConfigs()} disabled={!importText.trim() || importing}>
              <Upload />
              {importing ? t("servers.importing") : t("servers.import")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Exporting what a test run selected. The reason this exists is to carry
          the survivors of a test to another device — a phone, a television —
          and doing that one share dialog at a time is why it was asked for. */}
      <Dialog open={exportOpen} onOpenChange={setExportOpen}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("servers.export")}</DialogTitle>
            <DialogDescription>
              {t("servers.export.description", { count: exportLinks.length })}
              {exportSkipped > 0 && ` ${t("servers.export.skipped", { count: exportSkipped })}`}
            </DialogDescription>
          </DialogHeader>
          <Textarea
            readOnly
            value={exportText}
            className="h-64 min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
          />
          <DialogFooter className="sm:justify-between">
            <label className="flex items-center gap-2 text-sm sm:me-auto">
              <Switch checked={exportBase64} onCheckedChange={setExportBase64} />
              {t("servers.export.base64")}
            </label>
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button variant="outline" onClick={() => setExportOpen(false)}>
                {t("common.close")}
              </Button>
              <Button
                variant="outline"
                onClick={() => downloadTextFile(exportFilename, exportText)}
                disabled={!exportText}
              >
                <Download />
                {t("servers.export.download")}
              </Button>
              <Button onClick={() => void copyExport()} disabled={!exportText}>
                <Copy />
                {t("servers.copy")}
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
  sort: NodeSort | null;
  onSort: (column: NodeSortColumn) => void;
  className?: string;
  children: ReactNode;
}) {
  const active = sort?.column === column;
  return (
    <th className={cn("px-2 py-2 font-medium", className)}>
      <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={() => onSort(column)}>
        {children}
        {active && <ChevronDown className={cn("size-3", sort?.direction === "asc" && "rotate-180")} />}
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
        onSuccess(result.message || t("subs.imported", { count: result.imported }));
      } else {
        onError(result.message || t("subs.refreshFailed"));
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
        title={t("nav.subscriptions")}
        actions={
          <Button type="button" variant="outline" onClick={openNewSubscription}>
            <Plus />
            {t("subs.new")}
          </Button>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
            <div className="min-w-0">
              <p className="text-sm font-semibold">{t("subs.groups")}</p>
              <p className="text-xs text-muted-foreground">{t("subs.sources", { count: state.v2raySubscriptions.length })}</p>
            </div>
          </div>
          {state.v2raySubscriptions.length === 0 ? (
            <div className="px-3 py-4 text-sm text-muted-foreground">{t("subs.empty")}</div>
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
                    <th className="px-3 py-2 font-medium">{t("subs.column.name")}</th>
                    <th className="px-3 py-2 font-medium">{t("subs.column.url")}</th>
                    <th className="px-3 py-2 font-medium">{t("subs.column.profiles")}</th>
                    <th className="px-3 py-2 font-medium">{t("subs.column.status")}</th>
                    <th className="px-3 py-2 text-end font-medium">{t("servers.column.actions")}</th>
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
                              {builtIn ? t("subs.builtIn") : subscription.url}
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
                              <TooltipContent>{refreshing ? t("subs.refreshing") : t("subs.refresh")}</TooltipContent>
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
                                {builtIn
                                  ? t("subs.builtInStays")
                                  : deleteDisabled
                                    ? t("subs.disconnectFirst")
                                    : t("subs.deleteHint")}
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
            <DialogTitle>{draft.id ? draft.name : t("subs.new")}</DialogTitle>
            <DialogDescription>{t("subs.editor.description")}</DialogDescription>
          </DialogHeader>
          <FieldGroup className="grid gap-4">
            <TextField label={t("subs.column.name")} value={draft.name} onChange={(name) => setDraft({ ...draft, name })} />
            <TextField
              label={t("subs.editor.url")}
              value={draft.url}
              onChange={(url) => setDraft({ ...draft, url })}
              placeholder="https://example.com/sub"
            />
            {draft.lastError && (
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>{t("subs.lastRefreshFailed")}</AlertTitle>
                <AlertDescription>{draft.lastError}</AlertDescription>
              </Alert>
            )}
            {/* Offered once a refresh has failed, never before — but always
                shown while it is on, or it could not be turned back off. */}
            {(draft.lastError || draft.allowInsecureTls) && (
              <div className="grid gap-2 rounded-md border px-3 py-2">
                <label className="flex items-center justify-between gap-3 text-sm">
                  {t("subs.editor.allowInsecureTls")}
                  <Switch
                    checked={draft.allowInsecureTls}
                    onCheckedChange={(allowInsecureTls) => setDraft({ ...draft, allowInsecureTls })}
                  />
                </label>
                <p className="text-xs text-muted-foreground">{t("subs.editor.allowInsecureTlsHint")}</p>
              </div>
            )}
          </FieldGroup>
          <DialogFooter className="sm:justify-between">
            {draft.id ? (
              <Button type="button" variant="destructive" onClick={() => requestDeleteSubscription(draft)} className="sm:me-auto">
                <Trash2 />
                {t("subs.delete")}
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button type="button" variant="outline" onClick={() => setEditorOpen(false)}>
                {t("common.cancel")}
              </Button>
              {draft.id && (
                <Button type="button" variant="outline" disabled={Boolean(refreshingSubscriptionIds[draft.id])} onClick={() => refreshSubscription(draft)}>
                  <RotateCcw className={cn(refreshingSubscriptionIds[draft.id] && "animate-spin")} />
                  {t("subs.refresh")}
                </Button>
              )}
              <Button type="button" disabled={saveDisabled} onClick={saveSubscription}>
                <Save />
                {t("common.save")}
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("subs.deleteDialog.title")}</DialogTitle>
            <DialogDescription>
              {t("subs.deleteDialog.description", {
                name: deleteTarget?.name || t("subs.thisSubscription"),
                count: deleteTargetConfigCount,
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setDeleteTarget(null)}>
              {t("common.cancel")}
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
              {t("subs.deleteConfirm")}
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
    allowInsecureTls: false,
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
  t,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  t: TranslateFn;
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
      onSuccess(t("backup.restored"));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  return (
    <>
      <PageShell eyebrow={t("nav.tools")} title={t("nav.backup")}>
        <Card>
          <CardHeader>
            <CardTitle>{t("backup.card.title")}</CardTitle>
            <CardDescription>{t("backup.card.description")}</CardDescription>
          </CardHeader>
          <CardContent>
            <BackupRestoreSection
              t={t}
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
            <DialogDescription>{t("backup.export.description")}</DialogDescription>
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
              {t("backup.copyJson")}
            </Button>
            <Button
              type="button"
              onClick={() => downloadTextFile(`whitedns-backup-${new Date().toISOString().slice(0, 10)}.json`, backupText, "application/json;charset=utf-8")}
            >
              <FileText />
              {t("backup.downloadJson")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={restoreOpen} onOpenChange={setRestoreOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t("backup.restore.title")}</DialogTitle>
            <DialogDescription>{t("backup.restore.description")}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 space-y-4 overflow-auto pr-1">
            <Field>
              <FieldLabel>{t("backup.file")}</FieldLabel>
              <Input type="file" accept=".json,application/json,text/plain" onChange={(event) => importBackupFile(event.target.files?.[0] || null)} />
            </Field>
            <TextAreaField
              label={t("backup.json")}
              value={restoreText}
              onChange={setRestoreText}
              placeholder={'{\n  "schema": "whitedns.desktop.backup",\n  "version": 1\n}'}
              className="h-[min(45svh,20rem)] min-h-0 resize-none overflow-auto font-mono text-xs"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRestoreOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button disabled={restoreDisabled} onClick={restoreBackup}>
              <Upload />
              {t("backup.restore")}
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
  t,
}: {
  restoreLocked: boolean;
  onExportBackup: () => void;
  onOpenRestore: () => void;
  t: TranslateFn;
}) {
  return (
    <SettingsFieldSet legend={t("backup.section")}>
      <FieldGroup>
        <Field orientation="horizontal" className="items-center justify-between gap-4 rounded-lg border p-4">
          <FieldContent>
            <FieldTitle>{t("backup.export.title")}</FieldTitle>
            <FieldDescription>{t("backup.export.hint")}</FieldDescription>
          </FieldContent>
          <Button type="button" variant="outline" onClick={onExportBackup}>
            <FileText />
            {t("backup.export")}
          </Button>
        </Field>
        <Field orientation="horizontal" className="items-center justify-between gap-4 rounded-lg border p-4">
          <FieldContent>
            <FieldTitle>{t("backup.restore.fieldTitle")}</FieldTitle>
            <FieldDescription>{t("backup.restore.hint")}</FieldDescription>
          </FieldContent>
          <Button type="button" variant="outline" disabled={restoreLocked} onClick={onOpenRestore}>
            <Upload />
            {t("backup.restore")}
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
  t,
}: {
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  t: TranslateFn;
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
      setStatusText(t("whiteip.status.generated", { count: result.generated }));
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
      onSuccess(t("whiteip.status.imported", { profiles: result.imported, endpoints: result.whiteIpCount }));
      setStatusText(t("whiteip.status.converted", { count: result.sourceProfileCount }));
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
      setGeneratedDialog({ ...generatedDialog, copyStatus: t("whiteip.copied") });
    } catch {
      setGeneratedDialog({ ...generatedDialog, copyStatus: t("whiteip.copyFailed") });
    }
  }

  async function importWhiteIPFile(file: File | null) {
    if (!file) {
      return;
    }
    try {
      setWhiteIPText(await file.text());
      setStatusText(t("whiteip.status.loaded", { name: file.name }));
    } catch (err) {
      const message = messageFromError(err);
      setStatusText(message);
      onError(message);
    }
  }

  function resetDefaultWhiteIPs() {
    setWhiteIPText(defaultWhiteIPText);
    setStatusText(t("whiteip.status.reset"));
  }

  return (
    <>
    <PageShell
      eyebrow={t("nav.tools")}
      title={t("nav.whiteIps")}
      actions={
        <>
          <Button type="button" variant="outline" disabled={loadingDefault || !defaultWhiteIPText} onClick={resetDefaultWhiteIPs}>
            <RotateCcw />
            {t("whiteip.resetDefault")}
          </Button>
          <Button type="button" disabled={generateDisabled} onClick={generateWhiteIPProfiles}>
            <Share2 />
            {generating ? t("whiteip.generating") : t("whiteip.generate")}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
        <Card>
          <CardHeader>
            <CardTitle>{t("whiteip.source.title")}</CardTitle>
            <CardDescription>{t("whiteip.source.description")}</CardDescription>
          </CardHeader>
          <CardContent>
            <TextAreaField
              label={t("whiteip.source.label")}
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
                <CardTitle>{t("whiteip.list.title")}</CardTitle>
                <CardDescription>
                  {endpointLineCount ? t("whiteip.list.count", { count: endpointLineCount }) : t("whiteip.list.none")}
                </CardDescription>
              </div>
              {loadingDefault && <Badge variant="outline">{t("whiteip.loading")}</Badge>}
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field>
              <FieldLabel>{t("whiteip.importFile")}</FieldLabel>
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
              label={t("whiteip.endpoints")}
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
          <DialogTitle>{t("whiteip.dialog.title")}</DialogTitle>
          <DialogDescription>
            {generatedDialog
              ? t("whiteip.dialog.description", { configs: generatedDialog.generated, endpoints: generatedDialog.whiteIpCount })
              : t("whiteip.dialog.fallback")}
          </DialogDescription>
        </DialogHeader>
        <Textarea
          readOnly
          value={generatedDialog?.configText || ""}
          className="h-[min(56svh,28rem)] min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
        />
        <DialogFooter className="gap-2 sm:justify-between">
          <div className="min-h-5 text-xs font-medium text-muted-foreground">
            {generatedDialog?.copyStatus ||
              (generatedDialog ? t("whiteip.dialog.sources", { count: generatedDialog.sourceProfileCount }) : "")}
          </div>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button type="button" variant="outline" onClick={() => setGeneratedDialog(null)}>
              {t("common.close")}
            </Button>
            <Button type="button" variant="outline" disabled={!generatedDialog?.configText} onClick={copyGeneratedProfiles}>
              <Copy />
              {t("common.copy")}
            </Button>
            <Button type="button" disabled={!generatedDialog || importing} onClick={importWhiteIPProfiles}>
              <Download />
              {importing ? t("whiteip.importing") : t("whiteip.importAsProfiles")}
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
  t,
}: {
  state: ValidatorState;
  onState: (state: ValidatorState) => void;
  onAppState: (state: AppState) => void;
  onError: (message: string) => void;
  t: TranslateFn;
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
    setImportStatusText(t("validator.importing"));
    try {
      const text = await file.text();
      const result = await backend.parseValidatorRangeInput(text);
      const nextImportedSet = new Set(result.ranges.map((option) => option.range));
      setImportedFileName(file.name);
      setImportedRangeOptions(result.ranges);
      setSelectedRanges((current) => current.filter((range) => defaultRangeSet.has(range) || nextImportedSet.has(range)));

      const summary = [
        t("validator.import.imported", { count: formatCount(result.ranges.length) }),
        result.totalCount ? t("validator.import.inputs", { count: formatCount(result.totalCount) }) : "",
        result.duplicateCount ? t("validator.import.duplicates", { count: formatCount(result.duplicateCount) }) : "",
        result.invalidCount ? t("validator.import.invalid", { count: formatCount(result.invalidCount) }) : "",
      ].filter(Boolean).join(" · ");
      const invalidSample = result.invalid.length
        ? " " +
          t("validator.import.invalidSample", {
            list: result.invalid.join(", ") + (result.invalidCount > result.invalid.length ? ", ..." : ""),
          })
        : "";
      setImportStatusText(`${summary || t("validator.import.none")}${invalidSample}`);
      if (!result.ranges.length) {
        setInputError(result.totalCount ? t("validator.import.noRanges") : t("validator.import.empty"));
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
      eyebrow={t("nav.validator")}
      title={t("validator.title")}
    >
      <div className="grid gap-4 xl:grid-cols-[420px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>{t("validator.input.title")}</CardTitle>
            <CardDescription>{t("validator.testEndpointsFrom", { file: defaultValidatorRangeCSVName })}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={mode} onValueChange={(value) => setMode(value as "quick" | "bulk")}>
              <TabsList>
                <TabsTrigger value="quick">{t("validator.tab.quick")}</TabsTrigger>
                <TabsTrigger value="bulk">{t("validator.tab.bulk")}</TabsTrigger>
              </TabsList>
              <TabsContent value="quick" className="space-y-4 pt-4">
                <TextField label={t("validator.host")} value={host} onChange={setHost} placeholder="example.com" />
                <TextField label={t("validator.ports")} value={ports} onChange={setPorts} placeholder="53, 443" />
                <TextField label={t("validator.sni")} value={sni} onChange={setSni} placeholder="optional.example.com" />
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
                        {selectedRanges.length
                          ? t("validator.endpointCount", { count: formatCount(selectedRangeEndpointCount) })
                          : rangesLoading
                            ? t("whiteip.loading")
                            : t("validator.noRanges")}
                      </span>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <FieldLabel>{t("validator.ports")}</FieldLabel>
                        <span className="text-xs text-muted-foreground">
                          {rangePorts.length ? t("validator.portCount", { count: rangePorts.length }) : t("validator.noPorts")}
                        </span>
                      </div>
                      <Input
                        value={rangePortText}
                        disabled={running}
                        placeholder="443, 2053, 2083, 2087, 2096, 8443"
                        onChange={(event) => setRangePortText(event.target.value)}
                      />
                      <FieldDescription>{t("validator.ports.hint")}</FieldDescription>
                    </div>
                  </div>
                  {rangeSelectionTooLarge && (
                    <Alert variant="destructive">
                      <AlertCircle />
                      <AlertTitle>{t("validator.tooLarge")}</AlertTitle>
                      <AlertDescription>Select at most {formatCount(maxValidatorSelectedRangeHosts)} endpoints.</AlertDescription>
                    </Alert>
                  )}
                  {!rangePorts.length && (
                    <Alert variant="destructive">
                      <AlertCircle />
                      <AlertTitle>{t("validator.noPortsSelected")}</AlertTitle>
                      <AlertDescription>{t("validator.noPortsSelected.hint")}</AlertDescription>
                    </Alert>
                  )}
                  {rangePortParse.error && (
                    <Alert variant="destructive">
                      <AlertCircle />
                      <AlertTitle>{t("validator.invalidPorts")}</AlertTitle>
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
                      <TabsTrigger value="default">{t("validator.tab.default")}</TabsTrigger>
                      <TabsTrigger value="imported">{t("validator.tab.imported")}</TabsTrigger>
                    </TabsList>
                    <TabsContent value="default" className="space-y-3 pt-3">
                      <Input
                        value={rangeQuery}
                        disabled={running}
                        placeholder={t("validator.filterDefault")}
                        onChange={(event) => setRangeQuery(event.target.value)}
                      />
                      {rangeStatusText && (
                        <Alert variant="destructive">
                          <AlertCircle />
                          <AlertTitle>{t("validator.defaultUnavailable")}</AlertTitle>
                          <AlertDescription>{rangeStatusText}</AlertDescription>
                        </Alert>
                      )}
                      {renderRangeList(filteredRanges, rangesLoading, rangeQuery.trim() ? t("validator.noDefaultMatch") : t("validator.noDefault"))}
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
                        <FieldDescription>{t("validator.range.hint")}</FieldDescription>
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
                        placeholder={t("validator.filterImported")}
                        onChange={(event) => setRangeQuery(event.target.value)}
                      />
                      {renderRangeList(filteredRanges, false, rangeQuery.trim() ? t("validator.noImportedMatch") : t("validator.importToShow"))}
                    </TabsContent>
                  </Tabs>
                </FieldSet>
              </TabsContent>
            </Tabs>

            {inputError && (
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>{t("validator.inputError")}</AlertTitle>
                <AlertDescription>{inputError}</AlertDescription>
              </Alert>
            )}

            <Separator />
            <FieldSet>
              <FieldTitle className="text-base">Options</FieldTitle>
              <FieldGroup className="grid gap-3 sm:grid-cols-2">
                <NumberField label={t("validator.retries")} value={options.retries} min={1} max={8} onChange={(retries) => setOptions({ ...options, retries })} />
                <NumberField label={t("validator.timeout")} value={options.timeoutMillis} min={250} max={60000} onChange={(timeoutMillis) => setOptions({ ...options, timeoutMillis })} />
                <NumberField
                  label={t("validator.workers")}
                  value={validatorWorkerCountOption(options)}
                  min={1}
                  max={maxValidatorWorkers}
                  onChange={(workerCount) => {
                    const nextWorkerCount = clampValidatorWorkers(workerCount);
                    setOptions({ ...options, workerCount: nextWorkerCount, adaptiveLimit: nextWorkerCount });
                  }}
                />
                <TextField label={t("validator.httpPaths")} value={httpPaths} onChange={setHttpPaths} placeholder="/, /health" />
              </FieldGroup>
              <FieldGroup className="grid gap-1 pt-2 sm:grid-cols-2">
                <ToggleField label="UDP" checked={options.enableUdp} onChange={(enableUdp) => setOptions({ ...options, enableUdp })} />
                <ToggleField label="QUIC/H3" checked={options.enableQuic} onChange={(enableQuic) => setOptions({ ...options, enableQuic })} />
                <ToggleField label="DNS" checked={options.enableDns} onChange={(enableDns) => setOptions({ ...options, enableDns })} />
                <ToggleField label="WebSocket" checked={options.enableWebSocket} onChange={(enableWebSocket) => setOptions({ ...options, enableWebSocket })} />
                <ToggleField label={t("validator.insecureTls")} checked={options.allowInsecureCert} onChange={(allowInsecureCert) => setOptions({ ...options, allowInsecureCert })} />
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
                    {state.total > 0
                      ? t("validator.progress", { completed: state.completed, total: state.total })
                      : t("validator.idle")}
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
                    {t("validator.clear")}
                  </Button>
                  <Button variant="outline" disabled={!running || state.paused} onClick={() => setPaused(true)}>
                    <Pause />
                    {t("validator.pause")}
                  </Button>
                  <Button variant="outline" disabled={!running || !state.paused} onClick={() => setPaused(false)}>
                    <Play />
                    {t("validator.resume")}
                  </Button>
                  <Button variant="outline" disabled={!running} onClick={cancelScan}>
                    <Square />
                    {t("common.cancel")}
                  </Button>
                  <Button disabled={running || rangeSelectionTooLarge || (mode === "bulk" && (!rangePorts.length || Boolean(rangePortParse.error)))} onClick={startScan}>
                    <Search />
                    {t("validator.scan")}
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
                  <AlertTitle>{t("validator.failed")}</AlertTitle>
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
            t={t}
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
  t,
}: {
  files: ValidatorResultFile[];
  loading: boolean;
  statusText: string;
  t: TranslateFn;
  onRefresh: () => Promise<void>;
  onOpen: (name: string) => Promise<void>;
  onDelete: (name: string) => Promise<void>;
}) {
  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle>{t("validator.files.title")}</CardTitle>
            <CardDescription>{t("validator.files.description")}</CardDescription>
          </div>
          <Button type="button" variant="outline" onClick={onRefresh} disabled={loading}>
            <RotateCcw />
            {t("subs.refresh")}
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
              <EmptyTitle>{t("validator.files.empty")}</EmptyTitle>
              <EmptyDescription>{t("validator.files.empty.hint")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="overflow-x-auto rounded-lg border">
            <div className="min-w-[720px]">
              <div className="grid grid-cols-[minmax(220px,1fr)_92px_92px_110px_128px] items-center gap-2 border-b bg-muted/80 px-3 py-2 text-[10px] font-semibold uppercase text-muted-foreground">
                <div>{t("validator.files.column.file")}</div>
                <div>{t("validator.files.column.rows")}</div>
                <div>{t("subs.column.status")}</div>
                <div>{t("validator.files.column.size")}</div>
                <div className="text-end">{t("servers.column.actions")}</div>
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
                        {t("validator.files.open")}
                      </Button>
                      <Button type="button" variant="ghost" size="xs" onClick={() => onDelete(file.name)}>
                        <Trash2 />
                        {t("subs.delete")}
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
  t,
}: {
  runtime: RuntimeStatus;
  runtimeType: RuntimeType;
  title?: string;
  description?: string;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  t: TranslateFn;
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
  const title = titleOverride || t("logs.title");
  const description = descriptionOverride || t("logs.description");
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
      eyebrow={t("nav.logs")}
      title={title}
      actions={
        <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-end">
          <div className="relative w-full min-w-0 sm:w-80">
            <Search className="absolute start-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input className="ps-8" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("logs.search")} />
          </div>
          <Button type="button" variant="outline" onClick={copyLogs} disabled={!logs.length}>
            <Copy />
            {t("logs.copy")}
          </Button>
          <Button type="button" variant="outline" onClick={saveLogsFile} disabled={!logs.length}>
            <Download />
            {t("logs.save")}
          </Button>
          <Button type="button" variant="outline" onClick={clearLogs} disabled={!runtimeLogs.length}>
            <Trash2 />
            {t("logs.clear")}
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
                  <EmptyTitle>{t("logs.empty")}</EmptyTitle>
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


// The form behind the Servers page's edit button.
//
// Every field of a stored config, but not all at once: a vless node has no
// Shadowsocks method and a WireGuard peer has no SNI, and showing all of them
// together turns a config with six meaningful settings into a wall of fifty
// empty boxes. What is shown follows the protocol and the transport, which is
// the same thing the exporter looks at when it decides what to write.
//
// Only configs added by hand ever reach this. One from the catalogue or a
// subscription is a reading of what a provider is serving and returns unchanged
// at the next refresh, so it carries no profile and the button is not offered.
const transportOptions = ["tcp", "ws", "grpc", "h2", "httpupgrade", "xhttp"];
const protocolOptions: V2RayProtocol[] = ["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "wireguard", "socks", "http"];

function ManualNodeForm({
  profile,
  onChange,
  t,
}: {
  profile: V2RayProfile;
  onChange: (profile: V2RayProfile) => void;
  t: TranslateFn;
}) {
  const set = <K extends keyof V2RayProfile>(key: K, value: V2RayProfile[K]) => onChange({ ...profile, [key]: value });
  const protocol = normalizeV2RayProtocol(profile.protocol);
  const network = (profile.network || "tcp").toLowerCase();

  // Which protocols carry which credential. WireGuard is its own shape
  // entirely, which is why it takes over the section rather than adding to it.
  const usesUUID = protocol === "vless" || protocol === "vmess";
  const usesPassword = protocol === "trojan" || protocol === "shadowsocks" || protocol === "socks" || protocol === "http";
  const usesUsername = protocol === "socks" || protocol === "http";
  const isWireGuard = protocol === "wireguard";
  // Hysteria2 and WireGuard carry their own transport; the rest go through one
  // of the stream transports and can be given TLS.
  const usesTransport = !isWireGuard && protocol !== "hysteria2";
  const usesTLS = !isWireGuard;

  return (
    <div className="grid gap-4">
      <SettingsFieldSet legend={t("servers.edit.section.basics")}>
        <FieldGroup className="grid gap-3 md:grid-cols-2">
          <TextField label={t("servers.edit.name")} value={profile.name} onChange={(value) => set("name", value)} />
          <Field>
            <FieldLabel>{t("servers.edit.protocol")}</FieldLabel>
            <Select value={protocol} onValueChange={(value) => set("protocol", value as V2RayProtocol)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                {protocolOptions.map((option) => (
                  <SelectItem key={option} value={option}>
                    {option}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <TextField label={t("servers.edit.server")} value={profile.server} onChange={(value) => set("server", value)} />
          <NumberField
            label={t("servers.edit.port")}
            value={profile.serverPort}
            min={1}
            max={65535}
            onChange={(value) => set("serverPort", value)}
          />
        </FieldGroup>
      </SettingsFieldSet>

      <SettingsFieldSet legend={t("servers.edit.section.credentials")}>
        <FieldGroup className="grid gap-3 md:grid-cols-2">
          {usesUUID && <TextField label="UUID" value={profile.uuid} onChange={(value) => set("uuid", value)} />}
          {usesUsername && (
            <TextField label={t("servers.edit.username")} value={profile.username} onChange={(value) => set("username", value)} />
          )}
          {usesPassword && (
            <TextField label={t("servers.edit.password")} value={profile.password} onChange={(value) => set("password", value)} />
          )}
          {protocol === "shadowsocks" && (
            <TextField
              label={t("servers.edit.ssMethod")}
              value={profile.shadowsocksMethod}
              placeholder="aes-256-gcm"
              onChange={(value) => set("shadowsocksMethod", value)}
            />
          )}
          {protocol === "hysteria2" && (
            <>
              <TextField label={t("servers.edit.hysteriaAuth")} value={profile.hysteriaAuth} onChange={(value) => set("hysteriaAuth", value)} />
              <TextField
                label={t("servers.edit.hysteriaMasquerade")}
                value={profile.hysteriaMasquerade}
                onChange={(value) => set("hysteriaMasquerade", value)}
              />
            </>
          )}
          {protocol === "vmess" && (
            <>
              <NumberField label="alterId" value={profile.alterId} min={0} max={65535} onChange={(value) => set("alterId", value)} />
              <TextField label={t("servers.edit.security")} value={profile.security} placeholder="auto" onChange={(value) => set("security", value)} />
            </>
          )}
          {protocol === "vless" && (
            <TextField label="flow" value={profile.flow} placeholder="xtls-rprx-vision" onChange={(value) => set("flow", value)} />
          )}
          {isWireGuard && (
            <>
              <TextField
                label={t("servers.edit.wgSecretKey")}
                value={profile.wireGuardSecretKey}
                onChange={(value) => set("wireGuardSecretKey", value)}
              />
              <TextField
                label={t("servers.edit.wgPeerPublicKey")}
                value={profile.wireGuardPeerPublicKey}
                onChange={(value) => set("wireGuardPeerPublicKey", value)}
              />
              <TextField
                label={t("servers.edit.wgPreSharedKey")}
                value={profile.wireGuardPreSharedKey}
                onChange={(value) => set("wireGuardPreSharedKey", value)}
              />
              <TextField
                label={t("servers.edit.wgAddresses")}
                value={profile.wireGuardLocalAddresses}
                placeholder="172.16.0.2/32, fd00::2/128"
                onChange={(value) => set("wireGuardLocalAddresses", value)}
              />
              <TextField
                label={t("servers.edit.wgAllowedIps")}
                value={profile.wireGuardAllowedIps}
                placeholder="0.0.0.0/0, ::/0"
                onChange={(value) => set("wireGuardAllowedIps", value)}
              />
              <TextField
                label={t("servers.edit.wgReserved")}
                value={profile.wireGuardReserved}
                onChange={(value) => set("wireGuardReserved", value)}
              />
              <NumberField label="MTU" value={profile.wireGuardMtu} min={0} max={9000} onChange={(value) => set("wireGuardMtu", value)} />
              <NumberField
                label={t("servers.edit.wgKeepAlive")}
                value={profile.wireGuardKeepAlive}
                min={0}
                max={3600}
                onChange={(value) => set("wireGuardKeepAlive", value)}
              />
            </>
          )}
        </FieldGroup>
      </SettingsFieldSet>

      {usesTransport && (
        <SettingsFieldSet legend={t("servers.edit.section.transport")}>
          <FieldGroup className="grid gap-3 md:grid-cols-2">
            <Field>
              <FieldLabel>{t("servers.edit.transport")}</FieldLabel>
              <Select value={network} onValueChange={(value) => set("network", value)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper">
                  {transportOptions.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            {network === "grpc" ? (
              <TextField
                label={t("servers.edit.serviceName")}
                value={profile.serviceName}
                onChange={(value) => set("serviceName", value)}
              />
            ) : (
              <>
                <TextField label={t("servers.edit.path")} value={profile.transportPath} placeholder="/" onChange={(value) => set("transportPath", value)} />
                <TextField label={t("servers.edit.host")} value={profile.transportHost} onChange={(value) => set("transportHost", value)} />
              </>
            )}
            {network === "xhttp" && (
              <>
                <TextField label={t("servers.edit.xhttpMode")} value={profile.xhttpMode} placeholder="auto" onChange={(value) => set("xhttpMode", value)} />
                <TextField label={t("servers.edit.xhttpExtra")} value={profile.xhttpExtra} onChange={(value) => set("xhttpExtra", value)} />
              </>
            )}
            {(network === "ws" || network === "httpupgrade") && (
              <>
                <NumberField
                  label={t("servers.edit.wsEarlyData")}
                  value={profile.webSocketEarlyData}
                  min={0}
                  max={65535}
                  onChange={(value) => set("webSocketEarlyData", value)}
                />
                <TextField
                  label={t("servers.edit.wsEarlyDataHeader")}
                  value={profile.webSocketEarlyDataHeader}
                  onChange={(value) => set("webSocketEarlyDataHeader", value)}
                />
              </>
            )}
          </FieldGroup>
        </SettingsFieldSet>
      )}

      {usesTLS && (
        <SettingsFieldSet legend={t("servers.edit.section.tls")}>
          <FieldGroup className="grid gap-3 md:grid-cols-2">
            <ToggleField label="TLS" checked={profile.tls} onChange={(value) => set("tls", value)} />
            <ToggleField
              label={t("servers.edit.allowInsecure")}
              description={t("servers.edit.allowInsecure.hint")}
              checked={profile.allowInsecure}
              onChange={(value) => set("allowInsecure", value)}
            />
            <TextField label="SNI" value={profile.sni} onChange={(value) => set("sni", value)} />
            <TextField label="ALPN" value={profile.alpn} placeholder="h2,http/1.1" onChange={(value) => set("alpn", value)} />
            <TextField
              label={t("servers.edit.fingerprint")}
              value={profile.utlsFingerprint}
              placeholder="chrome"
              onChange={(value) => set("utlsFingerprint", value)}
            />
            <TextField label="ECH" value={profile.echConfigList} onChange={(value) => set("echConfigList", value)} />
            <ToggleField label="REALITY" checked={profile.reality} onChange={(value) => set("reality", value)} />
            {profile.reality && (
              <>
                <TextField
                  label={t("servers.edit.realityPublicKey")}
                  value={profile.realityPublicKey}
                  onChange={(value) => set("realityPublicKey", value)}
                />
                <TextField
                  label={t("servers.edit.realityShortId")}
                  value={profile.realityShortId}
                  onChange={(value) => set("realityShortId", value)}
                />
              </>
            )}
          </FieldGroup>
        </SettingsFieldSet>
      )}
    </div>
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
  // Tunnel mode needs the core raised to root, and that is implemented on
  // Windows only. Asked of the backend rather than guessed from the interface,
  // so the day another platform gains it this needs no change here.
  const [tunnelAvailable, setTunnelAvailable] = useState(true);
  useEffect(() => {
    void backend
      .tunnelSupported()
      .then(setTunnelAvailable)
      .catch(() => setTunnelAvailable(false));
  }, []);

  // The nodes a second hop can be chosen from: the selected subscription's, the
  // list the connection itself is built from. Loaded here rather than passed in,
  // because this is the only page that needs them and a settings page that
  // waits on the Servers page having been opened would be a settings page that
  // sometimes offers nothing.
  const [chainNodes, setChainNodes] = useState<WhiteVPNNode[]>([]);
  useEffect(() => {
    void backend
      .listWhiteVpnNodes(false)
      .then((list) => setChainNodes((list.nodes || []).filter((node) => !node.hidden)))
      .catch(() => setChainNodes([]));
  }, [state.selectedSubscriptionId]);

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
      <SettingsSection title={t("settings.chain.title")} description={t("settings.chain.description")}>
        <Field>
          <FieldLabel>{t("settings.chain.exit")}</FieldLabel>
          <Select
            value={draft.chainExitNode || "off"}
            onValueChange={(value) => patch({ chainExitNode: value === "off" ? "" : value })}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent position="popper">
              <SelectItem value="off">{t("settings.chain.off")}</SelectItem>
              {chainNodes.map((node) => (
                <SelectItem key={node.name} value={node.name}>
                  {node.label || node.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <FieldDescription>
            {draft.chainExitNode ? t("settings.chain.on.description") : t("settings.chain.off.description")}
          </FieldDescription>
        </Field>
        {/* The chosen node may have left the subscription since it was picked,
            which the connect path refuses rather than works around — so it is
            said here, where it can still be changed. */}
        {draft.chainExitNode && !chainNodes.some((node) => node.name === draft.chainExitNode) && (
          <Alert variant="destructive">
            <AlertCircle />
            <AlertDescription>{t("settings.chain.missing", { name: draft.chainExitNode })}</AlertDescription>
          </Alert>
        )}
      </SettingsSection>

      <SettingsSection title={t("settings.connection.title")} description={t("settings.connection.description")}>
        {/* One choice rather than two switches. The tunnel and the system proxy
            are mutually exclusive at connect — with the tunnel up the system
            proxy is deliberately not set — so two independent switches would
            silently override each other. */}
        <Field>
          <FieldLabel>{t("settings.routing.mode")}</FieldLabel>
          <Select
            value={routingMode(draft)}
            onValueChange={(value) =>
              patch(
                value === "tun"
                  ? { tunEnabled: true, setSystemProxy: false }
                  : { tunEnabled: false, setSystemProxy: value === "systemProxy" },
              )
            }
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent position="popper">
              <SelectItem value="systemProxy">{t("settings.routing.systemProxy")}</SelectItem>
              <SelectItem value="proxyOnly">{t("settings.routing.proxyOnly")}</SelectItem>
              {/* Offered only where it can run. A mode that always fails is
                  worse than one that is absent — the missing one does not waste
                  somebody's evening on an error about an unimplemented
                  function. */}
              {tunnelAvailable && <SelectItem value="tun">{t("settings.routing.tun")}</SelectItem>}
            </SelectContent>
          </Select>
          <FieldDescription>{t(`settings.routing.${routingMode(draft)}.description`)}</FieldDescription>
          {!tunnelAvailable && <FieldDescription>{t("settings.routing.tun.unavailable")}</FieldDescription>}
        </Field>

        {/* In proxy-only mode the port is the whole interface — it is what
            gets typed into Telegram. Everywhere else it stays hidden until
            sharing is on, because that is the only other moment a fixed number
            matters: a phone on the LAN has to be told an address, and it
            cannot follow a silent switch to a different port any more than
            Telegram could. */}
        {(routingMode(draft) === "proxyOnly" || draft.allowLan) && (
          <Field>
            <FieldLabel>{t("settings.routing.port")}</FieldLabel>
            <Input
              type="number"
              min={1024}
              max={65535}
              className="max-w-40"
              value={draft.listenPort || 2080}
              onChange={(event) => patch({ listenPort: Number(event.target.value) || 0 })}
            />
            <FieldDescription>
              {t("settings.routing.port.description", { endpoint: `127.0.0.1:${draft.listenPort || 2080}` })}
            </FieldDescription>
          </Field>
        )}

        <SettingSwitchRow
          label={t("settings.allowLan")}
          checked={draft.allowLan}
          onCheckedChange={(allowLan) => patch({ allowLan })}
        />
        <FieldDescription>{t("settings.allowLan.description")}</FieldDescription>
        {draft.allowLan && (
          <Alert>
            <AlertCircle />
            <AlertDescription>{t("settings.allowLan.warning")}</AlertDescription>
          </Alert>
        )}

        <SettingSwitchRow
          label={t("settings.killSwitch")}
          checked={draft.killSwitch.enabled}
          disabled
          onCheckedChange={(checked) => patch({ killSwitch: { enabled: checked } })}
        />
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

      <SettingsSection title={t("settings.update.title")} description={t("settings.update.description")}>
        <UpdateCheckRow t={t} />
      </SettingsSection>

      {/* The reversible one first. Both are called "reset", and the one that
          keeps your subscriptions is the one almost everybody wants — putting
          it second would have people reaching past it for the one that does
          not. */}
      <SettingsSection
        title={t("settings.resetSettings.title")}
        description={t("settings.resetSettings.description")}
      >
        <ResetSettingsRow onState={onState} onError={onError} onSuccess={onSuccess} t={t} />
      </SettingsSection>

      <SettingsSection title={t("settings.reset.title")} description={t("settings.reset.description")}>
        <ResetAppDataRow onState={onState} onError={onError} onSuccess={onSuccess} t={t} />
      </SettingsSection>
    </PageShell>
  );
}

// Asking for the check rather than waiting for it.
//
// The automatic one runs at startup and is cached for six hours, which is right
// for something nobody asked for. Someone who has just been told there is a new
// version and wants to see it should not have to wait out that cache, so this
// forces it — and then says what it found, including that it could not look,
// which on these networks is a normal answer rather than an error.
// Putting the settings back without taking anything with them.
//
// Behind a confirmation like its destructive neighbour, but the dialog's work is
// the opposite one: not warning that this cannot be undone, but saying plainly
// what it will not touch. The two sit next to each other and are both called
// "reset", so the difference has to be on screen rather than in the name.
function ResetSettingsRow({
  onState,
  onError,
  onSuccess,
  t,
}: {
  onState: (next: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  t: TranslateFn;
}) {
  const [asking, setAsking] = useState(false);
  const [working, setWorking] = useState(false);

  async function reset() {
    if (working) {
      return;
    }
    onError("");
    setWorking(true);
    try {
      onState(await backend.resetWhiteVpnSettings());
      setAsking(false);
      onSuccess(t("settings.resetSettings.done"));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setWorking(false);
    }
  }

  return (
    <>
      <div>
        <Button variant="outline" onClick={() => setAsking(true)}>
          <RotateCcw />
          {t("settings.resetSettings.button")}
        </Button>
      </div>

      <Dialog open={asking} onOpenChange={(open) => !open && !working && setAsking(false)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("settings.resetSettings.confirm.title")}</DialogTitle>
            <DialogDescription>{t("settings.resetSettings.confirm.body")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAsking(false)} disabled={working}>
              {t("common.cancel")}
            </Button>
            <Button onClick={() => void reset()} disabled={working}>
              <RotateCcw />
              {working ? t("settings.resetSettings.working") : t("settings.resetSettings.button")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

// Deleting everything the app has stored.
//
// Behind a confirmation because it cannot be undone and nothing is backed up
// first — the dialog says so, and points at the page that does take backups,
// rather than leaving someone to find out afterwards.
function ResetAppDataRow({
  onState,
  onError,
  onSuccess,
  t,
}: {
  onState: (next: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  t: TranslateFn;
}) {
  const [asking, setAsking] = useState(false);
  const [working, setWorking] = useState(false);

  async function reset() {
    if (working) {
      return;
    }
    onError("");
    setWorking(true);
    try {
      onState(await backend.resetAppData());
      setAsking(false);
      onSuccess(t("settings.reset.done"));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setWorking(false);
    }
  }

  return (
    <>
      <div>
        <Button variant="outline" className="text-destructive" onClick={() => setAsking(true)}>
          <Trash2 />
          {t("settings.reset.button")}
        </Button>
      </div>

      <Dialog open={asking} onOpenChange={(open) => !open && !working && setAsking(false)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("settings.reset.confirm.title")}</DialogTitle>
            <DialogDescription>{t("settings.reset.confirm.body")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAsking(false)} disabled={working}>
              {t("common.cancel")}
            </Button>
            <Button variant="destructive" onClick={() => void reset()} disabled={working}>
              <Trash2 />
              {working ? t("settings.reset.working") : t("settings.reset.button")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function UpdateCheckRow({ t }: { t: TranslateFn }) {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [checking, setChecking] = useState(false);

  async function check() {
    setChecking(true);
    try {
      setStatus(await backend.checkForUpdate(true));
    } catch {
      setStatus(null);
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant="outline" onClick={() => void check()} disabled={checking}>
        <ArrowUpCircle className={cn(checking && "animate-pulse")} />
        {checking ? t("update.checking") : t("update.check")}
      </Button>
      {status && !checking && (
        <span className="text-sm text-muted-foreground">
          {status.available ? (
            <button type="button" onClick={() => openExternalUrl(status.url)} className="text-primary hover:underline">
              {t("update.available", { version: status.latest })}
            </button>
          ) : status.current === "dev" ? (
            t("update.dev")
          ) : status.error ? (
            t("update.failed")
          ) : (
            t("update.upToDate", { version: status.current })
          )}
        </span>
      )}
    </div>
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
