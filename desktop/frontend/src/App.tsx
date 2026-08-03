import {
  Activity,
  AlertCircle,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  Copy,
  Cpu,
  Download,
  Eye,
  EyeOff,
  ExternalLink,
  FileText,
  Gauge,
  Globe2,
  GripVertical,
  LayoutDashboard,
  ListChecks,
  Monitor,
  Moon,
  Network,
  Pause,
  Pencil,
  Plus,
  Play,
  Power,
  Radio,
  RotateCcw,
  Save,
  ScrollText,
  Search,
  Server,
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
import QRCode from "qrcode";
import { useEffect, useMemo, useRef, useState } from "react";
import type { DragEvent, MouseEvent as ReactMouseEvent, PointerEvent as ReactPointerEvent, ReactNode, UIEvent as ReactUIEvent } from "react";

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
  CardAction,
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
  ItemGroup,
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
  useSidebar,
} from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useTheme, type Theme } from "@/components/theme-provider";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

import type {
  AppState,
  CloudflarePingResult,
  ConnectionProfile,
  ConnectionTestResolver,
  ConnectionTestResult,
  FirewallStatus,
  ImportType,
  ParallelTestPresetOption,
  ParallelTestState,
  ProxyCountryLookupResult,
  ResolverProfile,
  ResolverPreviewPage,
  ResolverRuntimeDetail,
  ResolverTextValidation,
  RuntimeLogEntry,
  RuntimeStatus,
  RuntimeStatusName,
  RuntimeType,
  ScannerState,
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

type Page = "dashboard" | "connections" | "resolvers" | "settings" | "logs" | "whitedns-vpn" | "whitedns-vpn-logs" | "v2ray-dashboard" | "v2ray-profiles" | "v2ray-subscriptions" | "v2ray-settings" | "v2ray-logs" | "v2ray-white-ips" | "scanner" | "validator" | "backup";
type NavItem = { id: Page; label: string; icon: ReactNode };
type NavGroup = { id: "masterdns" | "whitedns" | "v2ray" | "tools"; label: string; items: NavItem[] };
type V2RayPingSortDirection = "none" | "asc" | "desc";
type V2RayProfileTestKind = "" | "ping" | "speed" | "delay";
type V2RayProfileSortColumn = "none" | "delay" | "speed";
type V2RayStatusFilter = "all" | "reachable" | "failed" | "unchecked";
type V2RayTypeFilter = "all" | V2RayProtocol;
type V2RayProfileTableColumnId =
  | "select"
  | "type"
  | "remarks"
  | "address"
  | "port"
  | "transport"
  | "tls"
  | "delay"
  | "speed"
  | "actions";
type V2RayProfileTableColumn = {
  id: V2RayProfileTableColumnId;
  label: string;
  defaultWidth: number;
  minWidth: number;
  maxWidth: number;
  align?: "left" | "center" | "right";
  sticky?: "right";
};
type V2RayProfileSort = {
  column: V2RayProfileSortColumn;
  direction: V2RayPingSortDirection;
};
type V2RayProfileFilters = {
  status: V2RayStatusFilter;
  type: V2RayTypeFilter;
  subscriptionId: string;
};
type ValidatorStateUpdate = Omit<ValidatorState, "results"> & { results?: unknown; appendResults?: boolean };
type ConnectionProfileFilter = "all" | "reachable" | "disabled" | "unchecked";
type LanIpStatus = "idle" | "loading" | "ready" | "unavailable";
type V2RayPingState = {
  running: boolean;
  activeKind: V2RayProfileTestKind;
  results: Record<string, V2RayPingResult>;
  scanningIds: Record<string, boolean>;
  checkedAt: Record<string, number>;
};
type V2RayShareDialogState = {
  profile: V2RayProfile;
  link: string;
  qrDataUrl: string;
  qrError: string;
  copyStatus: string;
};
type ResolverCopyDialogState = {
  title: string;
  description: string;
  copyLabel: string;
  resolvers: string[];
  resolverDetails: ResolverRuntimeDetail[];
};
type SettingsSection =
  | "general"
  | "proxy"
  | "dns"
  | "traffic"
  | "mtu"
  | "performance"
  | "reliability";
type AppErrorToast = {
  id: number;
  message: string;
};

const defaultValidation: ResolverTextValidation = {
  normalizedResolvers: [],
  invalidEntries: [],
  normalizedText: "",
  isValid: false,
};
const runtimeLogLimit = 2000;
const resolverPreviewPageSize = 10000;
const defaultValidatorPort = 53;
const defaultValidatorRangePorts = [443, 2053, 2083, 2087, 2096, 8443];
const defaultValidatorRangeCSVName = "filtered_ipv4.csv";
const maxValidatorSelectedRangeHosts = 4000000;
const defaultValidatorWorkers = 128;
const maxValidatorWorkers = 2048;
const errorToastTTLMS = 6000;
const v2rayPingBatchSize = 128;
const v2rayRuntimeTestBatchSize = 4;
const v2rayProfileVirtualRowHeight = 40;
const v2rayProfileVirtualOverscan = 12;
const v2rayProfileTableColumnStorageKey = "whitedns.v2ray.profileTable.columnWidths.v2";
const v2rayProfileTableColumns: V2RayProfileTableColumn[] = [
  { id: "select", label: "", defaultWidth: 36, minWidth: 32, maxWidth: 52, align: "center" },
  { id: "type", label: "Type", defaultWidth: 60, minWidth: 52, maxWidth: 96 },
  { id: "remarks", label: "Remarks", defaultWidth: 128, minWidth: 88, maxWidth: 280 },
  { id: "address", label: "Address", defaultWidth: 104, minWidth: 80, maxWidth: 220 },
  { id: "port", label: "Port", defaultWidth: 52, minWidth: 44, maxWidth: 88 },
  { id: "transport", label: "Transport", defaultWidth: 78, minWidth: 64, maxWidth: 128 },
  { id: "tls", label: "TLS", defaultWidth: 48, minWidth: 40, maxWidth: 72 },
  { id: "delay", label: "Delay", defaultWidth: 64, minWidth: 56, maxWidth: 104, align: "right" },
  { id: "speed", label: "Speed", defaultWidth: 78, minWidth: 64, maxWidth: 128, align: "right" },
  { id: "actions", label: "Actions", defaultWidth: 128, minWidth: 112, maxWidth: 176, align: "right", sticky: "right" },
];
const dashboardNativeSelectThreshold = 500;
const whiteDnsTelegramUrl = "https://t.me/whitedns";
const whiteDNSVPNSubscriptionID = "whitedns-vpn";
const importTypeOptions: Array<[ImportType, string]> = [
  ["masterdns", "MasterDNS"],
  ["stormdns", "StormDNS"],
];
const v2rayProtocolOptions: Array<[V2RayProtocol, string]> = [
  ["vless", "VLESS"],
  ["vmess", "VMess"],
  ["trojan", "Trojan"],
  ["shadowsocks", "Shadowsocks"],
  ["hysteria2", "Hysteria2"],
  ["wireguard", "WireGuard"],
  ["socks", "SOCKS"],
  ["http", "HTTP"],
];
const v2rayNetworkOptions: Array<[string, string]> = [
  ["tcp", "TCP"],
  ["kcp", "mKCP"],
  ["ws", "WebSocket"],
  ["grpc", "gRPC"],
  ["http", "HTTP/2"],
  ["quic", "QUIC"],
  ["httpupgrade", "HTTPUpgrade"],
  ["xhttp", "XHTTP"],
];
const v2rayFlowNoneValue = "__none__";
const v2rayBaseFlowOptions: Array<[string, string]> = [
  [v2rayFlowNoneValue, "None"],
  ["xtls-rprx-vision", "XTLS Vision"],
];
const v2raySubscriptionFilterAll = "__all_v2ray_subscriptions__";
const v2raySubscriptionFilterManual = "__manual_v2ray_profiles__";
const v2rayProfileStatusFilterOptions: Array<[V2RayStatusFilter, string]> = [
  ["all", "All"],
  ["reachable", "Reachable"],
  ["failed", "Failed"],
  ["unchecked", "Unchecked"],
];
const v2rayProfileTypeFilterOptions: Array<[V2RayTypeFilter, string]> = [
  ["all", "All"],
  ...v2rayProtocolOptions,
];
const enhancedConnectionLabel = "Enhanced Connection";
const iranRoutingDescription = [
  "Private/local IPs go direct, not through V2Ray.",
  "Iranian domains/IPs from geosite-ir and geoip-ir go direct.",
  "Ads, malware, phishing, cryptominers, and related bad IP/domain rule sets are blocked.",
  "Everything else still goes through the selected V2Ray proxy.",
  "Rule files are bundled with the app and loaded locally.",
].join("\n");
const connectionProfileFilterOptions: Array<[ConnectionProfileFilter, string]> = [
  ["all", "All"],
  ["reachable", "Reachable"],
  ["disabled", "Disabled"],
  ["unchecked", "Unchecked"],
];
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

function importTypeLabel(value?: string): string {
  return normalizeImportType(value) === "stormdns" ? "StormDNS" : "MasterDNS";
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

function filterRecordKeys<T>(record: Record<string, T>, allowedIds: Set<string>): Record<string, T> {
  let changed = false;
  const next: Record<string, T> = {};
  for (const [id, value] of Object.entries(record)) {
    if (allowedIds.has(id)) {
      next[id] = value;
    } else {
      changed = true;
    }
  }
  return changed ? next : record;
}

function omitRecordKeys<T>(record: Record<string, T>, ids: Set<string>): Record<string, T> {
  if (!ids.size) {
    return record;
  }
  let changed = false;
  const next: Record<string, T> = {};
  for (const [id, value] of Object.entries(record)) {
    if (ids.has(id)) {
      changed = true;
    } else {
      next[id] = value;
    }
  }
  return changed ? next : record;
}

function clampNumber(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function defaultV2RayProfileTableColumnWidths(): Record<V2RayProfileTableColumnId, number> {
  return Object.fromEntries(v2rayProfileTableColumns.map((column) => [column.id, column.defaultWidth])) as Record<V2RayProfileTableColumnId, number>;
}

function normalizeV2RayProfileTableColumnWidths(input: unknown): Record<V2RayProfileTableColumnId, number> {
  const source = input && typeof input === "object" ? (input as Partial<Record<V2RayProfileTableColumnId, unknown>>) : {};
  return Object.fromEntries(
    v2rayProfileTableColumns.map((column) => {
      const raw = Number(source[column.id]);
      const width = Number.isFinite(raw) ? raw : column.defaultWidth;
      return [column.id, clampNumber(Math.round(width), column.minWidth, column.maxWidth)];
    })
  ) as Record<V2RayProfileTableColumnId, number>;
}

function loadV2RayProfileTableColumnWidths(): Record<V2RayProfileTableColumnId, number> {
  if (typeof window === "undefined") {
    return defaultV2RayProfileTableColumnWidths();
  }
  try {
    return normalizeV2RayProfileTableColumnWidths(JSON.parse(window.localStorage.getItem(v2rayProfileTableColumnStorageKey) || "{}"));
  } catch {
    return defaultV2RayProfileTableColumnWidths();
  }
}

function v2rayProfileTableWidth(widths: Record<V2RayProfileTableColumnId, number>): number {
  return v2rayProfileTableColumns.reduce((total, column) => total + widths[column.id], 0);
}

function mergeV2RayPingResult(previous: V2RayPingResult | undefined, next: V2RayPingResult, kind: V2RayProfileTestKind): V2RayPingResult {
  const base: V2RayPingResult = {
    ...(previous || {}),
    ...next,
    ok: Boolean(next.ok),
    speedOk: Boolean(next.speedOk),
    delayOk: Boolean(next.delayOk),
    downloadBytesPerSecond: next.downloadBytesPerSecond || 0,
    speedTestBytes: next.speedTestBytes || 0,
    speedTestDurationMs: next.speedTestDurationMs || 0,
    realDelayMs: next.realDelayMs || 0,
    speedMessage: next.speedMessage || "",
    delayMessage: next.delayMessage || "",
  };
  if (kind === "speed") {
    return {
      ...base,
      delayOk: Boolean(previous?.delayOk),
      realDelayMs: previous?.realDelayMs || 0,
      delayMessage: previous?.delayMessage || "",
    };
  }
  if (kind === "delay") {
    return {
      ...base,
      speedOk: Boolean(previous?.speedOk),
      downloadBytesPerSecond: previous?.downloadBytesPerSecond || 0,
      speedTestBytes: previous?.speedTestBytes || 0,
      speedTestDurationMs: previous?.speedTestDurationMs || 0,
      speedMessage: previous?.speedMessage || "",
    };
  }
  return {
    ...base,
    speedOk: Boolean(previous?.speedOk),
    downloadBytesPerSecond: previous?.downloadBytesPerSecond || 0,
    speedTestBytes: previous?.speedTestBytes || 0,
    speedTestDurationMs: previous?.speedTestDurationMs || 0,
    speedMessage: previous?.speedMessage || "",
    delayOk: Boolean(previous?.delayOk),
    realDelayMs: previous?.realDelayMs || 0,
    delayMessage: previous?.delayMessage || "",
  };
}

function normalizeParallelTestState(state: ParallelTestState | null | undefined): ParallelTestState {
  const next = state || defaultParallelTestState;
  return {
    ...defaultParallelTestState,
    ...next,
    total: Number(next.total || 0),
    completed: Number(next.completed || 0),
    running: Number(next.running || 0),
    resolverTarget: Number(next.resolverTarget || defaultParallelTestState.resolverTarget),
    resolvers: Array.isArray(next.resolvers) ? next.resolvers : [],
    candidates: Array.isArray(next.candidates)
      ? next.candidates.map((candidate) => ({
        id: candidate.id || "",
        name: candidate.name || "",
        status: candidate.status || "pending",
        stability: Number(candidate.stability || 0),
        rttMs: Number(candidate.rttMs || 0),
        score: Number(candidate.score || 0),
        startDurationMs: Number(candidate.startDurationMs || 0),
        downloadBytesPerSecond: Number(candidate.downloadBytesPerSecond || 0),
        speedTestBytes: Number(candidate.speedTestBytes || 0),
        speedTestDurationMs: Number(candidate.speedTestDurationMs || 0),
        speedTestError: candidate.speedTestError || "",
        error: candidate.error || "",
      }))
      : [],
    winnerPresetId: next.winnerPresetId || "",
    winnerPresetName: next.winnerPresetName || "",
    error: next.error || "",
    startedAt: Number(next.startedAt || 0),
    finishedAt: Number(next.finishedAt || 0),
  };
}

function isFileBackedResolver(profile?: ResolverProfile): boolean {
  return profile?.resolverSource === "file" && Boolean(profile.resolverFile);
}

function settingsProfileNameKey(name: string): string {
  return name.trim().replace(/\s+/g, " ").toLowerCase();
}

function settingsSelectionId(id: string): string {
  return `settings:${id}`;
}

function builtinSelectionId(id: string): string {
  return `builtin:${id}`;
}

function dedupeStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function defaultParallelConfigSelection(state: AppState, builtIns: ParallelTestPresetOption[]): string[] {
  const recommendedBuiltIns = new Set([
    "iran-default",
    "iran-fast-low-mtu",
    "iran-mid-reliable",
    "iran-download-heavy",
  ]);
  const ids: string[] = [];
  if (state.selectedSettingsProfileId) {
    ids.push(settingsSelectionId(state.selectedSettingsProfileId));
  }
  for (const option of builtIns.filter((option) => recommendedBuiltIns.has(option.id))) {
    ids.push(builtinSelectionId(option.id));
  }
  return dedupeStrings(ids);
}

function sanitizeParallelConfigSelection(ids: string[], state: AppState, builtIns: ParallelTestPresetOption[]): string[] {
  const valid = new Set<string>([
    ...state.settingsProfiles.map((profile) => settingsSelectionId(profile.id)),
    ...builtIns.map((option) => builtinSelectionId(option.id)),
  ]);
  return dedupeStrings(ids.filter((id) => valid.has(id)));
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

function masterDNSRuntimeActive(state: AppState): boolean {
  return runtimeTypeForState(state) === "masterdns";
}

function v2RayRuntimeActive(state: AppState): boolean {
  return runtimeTypeForState(state) === "v2ray";
}

function whiteDNSVPNRuntimeActive(state: AppState): boolean {
  return v2RayRuntimeActive(state) && state.v2rayProfiles.some((profile) => (
    profile.id === state.runtime.activeConnectionId && profile.subscriptionId === whiteDNSVPNSubscriptionID
  ));
}

function effectiveResolverProfileId(state: AppState): string {
  const connection =
    (masterDNSRuntimeActive(state) ? state.connectionProfiles.find((profile) => profile.id === state.runtime.activeConnectionId) : undefined) ||
    state.connectionProfiles.find((profile) => profile.id === state.selectedConnectionProfileId);
  const connectionResolverID = connection?.resolverProfileId || "";
  if (connectionResolverID && state.resolverProfiles.some((profile) => profile.id === connectionResolverID)) {
    return connectionResolverID;
  }
  return state.selectedResolverProfileId;
}

function makeResolverProfileId(profiles: ResolverProfile[]): string {
  const existing = new Set(profiles.map((profile) => profile.id));
  const base = `resolver-${Date.now()}`;
  let id = base;
  for (let attempt = 1; existing.has(id); attempt += 1) {
    id = `${base}-${attempt}`;
  }
  return id;
}

function makeConnectionProfileId(profiles: ConnectionProfile[]): string {
  const existing = new Set(profiles.map((profile) => profile.id));
  const base = `profile-${Date.now()}`;
  let id = base;
  for (let attempt = 1; existing.has(id); attempt += 1) {
    id = `${base}-${attempt}`;
  }
  return id;
}

function makeV2RayProfileId(profiles: V2RayProfile[]): string {
  const existing = new Set(profiles.map((profile) => profile.id));
  const base = `v2ray-${Date.now()}`;
  let id = base;
  for (let attempt = 1; existing.has(id); attempt += 1) {
    id = `${base}-${attempt}`;
  }
  return id;
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

function effectiveConnectionProfile(state: AppState): ConnectionProfile | undefined {
  const activeConnection = profileSelectionLocked(state.runtime) && masterDNSRuntimeActive(state)
    ? state.connectionProfiles.find((profile) => profile.id === state.runtime.activeConnectionId)
    : undefined;
  return (
    activeConnection ||
    state.connectionProfiles.find((profile) => profile.id === state.selectedConnectionProfileId) ||
    state.connectionProfiles[0]
  );
}

function effectiveV2RayProfile(state: AppState): V2RayProfile | undefined {
  const activeProfile = profileSelectionLocked(state.runtime) && v2RayRuntimeActive(state)
    ? state.v2rayProfiles.find((profile) => profile.id === state.runtime.activeConnectionId)
    : undefined;
  return (
    activeProfile ||
    state.v2rayProfiles.find((profile) => profile.id === state.selectedV2RayProfileId) ||
    state.v2rayProfiles[0]
  );
}

function effectiveV2RaySettingsProfile(state: AppState): V2RaySettingsProfile | undefined {
  return (
    state.v2raySettingsProfiles.find((profile) => profile.id === state.selectedV2RaySettingsId) ||
    state.v2raySettingsProfiles[0]
  );
}

function resolverProfileCount(profile?: ResolverProfile, validation?: ResolverTextValidation): number {
  if (!profile) {
    return 0;
  }
  if (isFileBackedResolver(profile)) {
    return profile.resolverCount || 0;
  }
  return validation?.normalizedResolvers.length || profile.resolverText.split("\n").filter(Boolean).length || 0;
}

function resolverProfilePreviewLabel(profile: ResolverProfile): string {
  const entries = (isFileBackedResolver(profile) ? profile.resolverPreview || [] : profile.resolverText.split(/\r?\n/))
    .map((resolver) => resolver.trim())
    .filter(Boolean);
  return entries.slice(0, 2).join(", ") || "No resolvers";
}

function validationFromFileBackedResolver(profile: ResolverProfile): ResolverTextValidation {
  return {
    normalizedResolvers: profile.resolverPreview || [],
    invalidEntries: [],
    normalizedText: "",
    isValid: (profile.resolverCount || 0) > 0,
  };
}

function resolverRuntimeCount(resolvers: string[] | null, count?: number): number {
  return count && count > 0 ? count : resolvers?.length || 0;
}

function hasLiveResolverCounts(runtime: RuntimeStatus): boolean {
  return (runtime.resolverState.totalCount || 0) > 0;
}

function liveRejectedResolverCount(runtime: RuntimeStatus): number {
  return hasLiveResolverCounts(runtime)
    ? runtime.resolverState.rejectedCount || 0
    : runtime.progress.rejected || 0;
}

function resolverRuntimeComplete(resolvers: string[] | null, count: number | undefined, complete: boolean | undefined): boolean {
  if (complete) {
    return true;
  }
  const resolverCount = resolvers?.length || 0;
  return resolverCount > 0 && resolverCount === (count || resolverCount);
}

function displayFileName(path?: string): string {
  if (!path) {
    return "Managed resolver file";
  }
  const normalized = path.replace(/\\/g, "/");
  return normalized.split("/").filter(Boolean).pop() || "Managed resolver file";
}

function proxyEndpoint(ip?: string, port?: number): string {
  return ip && port ? `${ip}:${port}` : "";
}

type ProxyCountryInfo = {
  icon: string;
  name: string;
};

type RegionDisplayNames = {
  of(code: string): string | undefined;
};

type RegionDisplayNamesConstructor = new (
  locales: string[],
  options: { type: "region" }
) => RegionDisplayNames;

function proxyCountryInfo(
  connection?: ConnectionProfile,
  settings?: SettingsProfile,
  runtime?: RuntimeStatus,
  lookup?: ProxyCountryLookupResult | null,
  lookupRunning = false
): ProxyCountryInfo {
  const lookupCode = normalizeCountryCode(lookup?.countryCode);
  if (lookup?.ok && lookupCode) {
    return {
      icon: countryFlagEmoji(lookupCode),
      name: countryNameFromCode(lookupCode),
    };
  }
  if (lookupRunning) {
    return { icon: "🌐", name: "Looking up" };
  }

  const source = [
    runtime?.autoProfileName,
    settings?.name,
    connection?.name,
    connection?.domain,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  if (source.includes("iran") || source.includes(".ir")) {
    return { icon: "🇮🇷", name: "Iran" };
  }
  if (source.includes("turkey") || source.includes(".tr")) {
    return { icon: "🇹🇷", name: "Turkey" };
  }
  if (source.includes("germany") || source.includes(".de")) {
    return { icon: "🇩🇪", name: "Germany" };
  }
  if (source.includes("netherlands") || source.includes(".nl")) {
    return { icon: "🇳🇱", name: "Netherlands" };
  }
  if (source.includes("france") || source.includes(".fr")) {
    return { icon: "🇫🇷", name: "France" };
  }
  if (source.includes("usa") || source.includes("united states") || source.includes(".us")) {
    return { icon: "🇺🇸", name: "United States" };
  }
  return { icon: "🌐", name: "Auto" };
}

function normalizeCountryCode(code?: string): string {
  const normalized = (code || "").trim().toUpperCase();
  return /^[A-Z]{2}$/.test(normalized) ? normalized : "";
}

function countryFlagEmoji(code: string): string {
  const normalized = normalizeCountryCode(code);
  if (!normalized) {
    return "🌐";
  }
  return Array.from(normalized)
    .map((char) => String.fromCodePoint(127397 + char.charCodeAt(0)))
    .join("");
}

function countryFlagFromProfileName(value?: string): string {
  return value?.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u)?.[0] || "🌐";
}

function countryNameFromCode(code: string): string {
  const normalized = normalizeCountryCode(code);
  if (!normalized) {
    return "Auto";
  }
  try {
    const DisplayNames = (Intl as typeof Intl & { DisplayNames?: RegionDisplayNamesConstructor }).DisplayNames;
    if (!DisplayNames) {
      return normalized;
    }
    return new DisplayNames(["en"], { type: "region" }).of(normalized) || normalized;
  } catch {
    return normalized;
  }
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

const defaultScannerState: ScannerState = {
  status: "idle",
  mode: "manual",
  paused: false,
  phase: "",
  message: "",
  selectedConnectionProfileId: "",
  inputFileName: "",
  scanParallel: 200,
  bootstrapResolverCount: 0,
  restartAvailable: false,
  autoRestart: false,
  scannedResolverCount: 0,
  total: 0,
  completed: 0,
  valid: 0,
  rejected: 0,
  invalid: 0,
  duplicates: 0,
  validResolvers: [],
  error: "",
  startedAt: 0,
  finishedAt: 0,
};

const defaultParallelTestState: ParallelTestState = {
  status: "idle",
  phase: "",
  message: "",
  total: 0,
  completed: 0,
  running: 0,
  resolverTarget: 1,
  resolvers: [],
  candidates: [],
  winnerPresetId: "",
  winnerPresetName: "",
  error: "",
  startedAt: 0,
  finishedAt: 0,
};

const navGroups: NavGroup[] = [
  {
    id: "masterdns",
    label: "MasterDNS",
    items: [
      { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard /> },
      { id: "connections", label: "Connections", icon: <Network /> },
      { id: "resolvers", label: "Resolvers", icon: <Globe2 /> },
      { id: "settings", label: "Settings", icon: <Settings /> },
      { id: "logs", label: "Logs", icon: <ScrollText /> },
    ],
  },
	{
		id: "whitedns",
		label: "WhiteDNS VPN",
		items: [
			{ id: "whitedns-vpn", label: "WhiteDNS VPN", icon: <Power /> },
			{ id: "whitedns-vpn-logs", label: "Logs", icon: <ScrollText /> },
		],
	},
  {
    id: "v2ray",
    label: "V2Ray",
    items: [
      { id: "v2ray-profiles", label: "Dashboard", icon: <Shield /> },
      { id: "v2ray-subscriptions", label: "Subscriptions", icon: <ListChecks /> },
      { id: "v2ray-settings", label: "Settings", icon: <Settings /> },
      { id: "v2ray-logs", label: "Logs", icon: <ScrollText /> },
    ],
  },
  {
    id: "tools",
    label: "Tools",
    items: [
      { id: "v2ray-white-ips", label: "V2Ray White IP Generator", icon: <Share2 /> },
      { id: "scanner", label: "DNS Scanner", icon: <Search /> },
      { id: "validator", label: "Validator", icon: <ListChecks /> },
      { id: "backup", label: "Full Backup", icon: <Save /> },
    ],
  },
];

const settingsSections: Array<{ id: SettingsSection; label: string; icon: ReactNode }> = [
  { id: "general", label: "General", icon: <SlidersHorizontal /> },
  { id: "proxy", label: "Proxy", icon: <Server /> },
  { id: "dns", label: "DNS", icon: <Radio /> },
  { id: "traffic", label: "Traffic", icon: <Activity /> },
  { id: "mtu", label: "MTU", icon: <Gauge /> },
  { id: "performance", label: "Performance", icon: <Cpu /> },
  { id: "reliability", label: "Reliability", icon: <Shield /> },
];

function App() {
  const [state, setState] = useState<AppState | null>(null);
  const [page, setPage] = useState<Page>("dashboard");
  const [settingsSection, setSettingsSection] = useState<SettingsSection>("general");
  const [errorToast, setErrorToast] = useState<AppErrorToast | null>(null);
  const [successToast, setSuccessToast] = useState<AppErrorToast | null>(null);
  const [toml, setToml] = useState("");
  const [resolverValidation, setResolverValidation] = useState(defaultValidation);
  const [scannerState, setScannerState] = useState<ScannerState>(defaultScannerState);
  const [validatorState, setValidatorState] = useState<ValidatorState>(defaultValidatorState);
  const [parallelTestState, setParallelTestState] = useState<ParallelTestState>(defaultParallelTestState);
  const [parallelPresetOptions, setParallelPresetOptions] = useState<ParallelTestPresetOption[]>([]);
  const [parallelConfigDialogOpen, setParallelConfigDialogOpen] = useState(false);
  const [parallelSelectedConfigIds, setParallelSelectedConfigIds] = useState<string[]>([]);
  const [v2rayPingRunning, setV2RayPingRunning] = useState(false);
  const [v2rayPingActiveKind, setV2RayPingActiveKind] = useState<V2RayProfileTestKind>("");
  const [v2rayPingResults, setV2RayPingResults] = useState<Record<string, V2RayPingResult>>({});
  const [v2rayPingScanningIds, setV2RayPingScanningIds] = useState<Record<string, boolean>>({});
  const [v2rayPingCheckedAt, setV2RayPingCheckedAt] = useState<Record<string, number>>({});
  const runtimeLogBufferRef = useRef<RuntimeLogEntry[]>([]);
  const runtimeLogFlushTimerRef = useRef<number | null>(null);
  const v2rayPingRunRef = useRef(0);

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
      .getValidatorState()
      .then(applyValidatorState)
      .catch((err) => showError(messageFromError(err)));
    backend
      .getScannerState()
      .then(setScannerState)
      .catch((err) => showError(messageFromError(err)));
    backend
      .getParallelTestState()
      .then((next) => setParallelTestState(normalizeParallelTestState(next)))
      .catch((err) => showError(messageFromError(err)));
    backend
      .getParallelTestPresetOptions()
      .then(setParallelPresetOptions)
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
      onRuntimeEvent<AppState>("app:state", applyState),
      onRuntimeEvent<ValidatorStateUpdate>("validator:state", applyValidatorState),
      onRuntimeEvent<ValidatorStateUpdate>("validator:progress", applyValidatorState),
      onRuntimeEvent<ScannerState>("scanner:state", setScannerState),
      onRuntimeEvent<ParallelTestState>("parallel-test:state", (next) => {
        const normalized = normalizeParallelTestState(next);
        setParallelTestState(normalized);
        if (normalized.status === "failed" && normalized.error) {
          showError(normalized.error);
        }
      }),
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

  const selectedConnection = useMemo(() => {
    return state ? effectiveConnectionProfile(state) : undefined;
  }, [state]);

  const selectedResolver = useMemo(() => {
    if (!state) {
      return undefined;
    }
    const connectionResolverID = selectedConnection?.resolverProfileId || "";
    const connectionResolver = connectionResolverID
      ? state.resolverProfiles.find((profile) => profile.id === connectionResolverID)
      : undefined;
    return connectionResolver || state.resolverProfiles.find((profile) => profile.id === state.selectedResolverProfileId);
  }, [selectedConnection, state]);

  const selectedSettings = useMemo(() => {
    return state?.settingsProfiles.find((profile) => profile.id === state.selectedSettingsProfileId);
  }, [state]);

  useEffect(() => {
    if (!state) {
      return;
    }
    const profileIds = new Set(state.v2rayProfiles.map((profile) => profile.id));
    setV2RayPingResults((current) => filterRecordKeys(current, profileIds));
    setV2RayPingScanningIds((current) => filterRecordKeys(current, profileIds));
    setV2RayPingCheckedAt((current) => filterRecordKeys(current, profileIds));
  }, [state?.v2rayProfiles]);

  useEffect(() => {
    if (!selectedResolver) {
      setResolverValidation(defaultValidation);
      return;
    }
    if (isFileBackedResolver(selectedResolver)) {
      setResolverValidation(validationFromFileBackedResolver(selectedResolver));
      return;
    }
    backend
      .validateResolverText(selectedResolver.resolverText)
      .then(setResolverValidation)
      .catch(() => setResolverValidation(defaultValidation));
  }, [selectedResolver?.id, selectedResolver?.resolverText, selectedResolver?.resolverSource, selectedResolver?.resolverCount]);

  function forgetV2RayPingProfiles(ids: string[]) {
    const remove = new Set(ids.filter(Boolean));
    if (!remove.size) {
      return;
    }
    setV2RayPingResults((current) => omitRecordKeys(current, remove));
    setV2RayPingScanningIds((current) => omitRecordKeys(current, remove));
    setV2RayPingCheckedAt((current) => omitRecordKeys(current, remove));
  }

  async function runV2RayProfileTests(
    profiles: V2RayProfile[],
    runBatch: (ids: string[]) => Promise<V2RayPingResult[]>,
    options: { batchSize?: number; clearExisting?: boolean; kind?: V2RayProfileTestKind; requireSpeedOk?: boolean; skippedLabel?: string } = {}
  ): Promise<{ completed: boolean; results: V2RayPingResult[] }> {
    clearErrorToast();
    const requestedIds = Array.from(new Set(profiles.map((profile) => profile.id).filter(Boolean)));
    const profileIdsToPing = options.requireSpeedOk ? requestedIds.filter((id) => v2rayPingResults[id]?.speedOk) : requestedIds;
    const batchSize = Math.max(1, Math.floor(options.batchSize || v2rayPingBatchSize));
    const skippedCount = requestedIds.length - profileIdsToPing.length;
    if (skippedCount > 0) {
      showSuccess(`Skipped ${skippedCount} V2Ray profile${skippedCount === 1 ? "" : "s"} without a successful speed test.`);
    }
    const runId = v2rayPingRunRef.current + 1;
    v2rayPingRunRef.current = runId;

    setV2RayPingRunning(Boolean(profileIdsToPing.length));
    setV2RayPingActiveKind(profileIdsToPing.length ? options.kind || "ping" : "");
    setV2RayPingScanningIds(Object.fromEntries(profileIdsToPing.map((id) => [id, true])));
    if (options.clearExisting) {
      setV2RayPingResults((current) => {
        const next = { ...current };
        profileIdsToPing.forEach((id) => {
          delete next[id];
        });
        return next;
      });
    }

    if (!profileIdsToPing.length) {
      return { completed: true, results: [] };
    }

    const allResults: V2RayPingResult[] = [];
    try {
      for (let idx = 0; idx < profileIdsToPing.length; idx += batchSize) {
        const batchIds = profileIdsToPing.slice(idx, idx + batchSize);
        const batchResults = await runBatch(batchIds);
        if (v2rayPingRunRef.current !== runId) {
          return { completed: false, results: allResults };
        }
        const checkedAt = Date.now();
        if (batchResults.length) {
          allResults.push(...batchResults);
          setV2RayPingResults((current) => {
            const next = { ...current };
            batchResults.forEach((result) => {
              next[result.profileId] = mergeV2RayPingResult(next[result.profileId], result, options.kind || "");
            });
            return next;
          });
          setV2RayPingCheckedAt((current) => {
            const next = { ...current };
            batchResults.forEach((result) => {
              next[result.profileId] = checkedAt;
            });
            return next;
          });
        }
        setV2RayPingScanningIds((current) => {
          const next = { ...current };
          batchIds.forEach((id) => {
            delete next[id];
          });
          return next;
        });
      }
    } catch (err) {
      if (v2rayPingRunRef.current === runId) {
        showError(messageFromError(err));
      }
      return { completed: false, results: allResults };
    } finally {
      if (v2rayPingRunRef.current === runId) {
        setV2RayPingRunning(false);
        setV2RayPingActiveKind("");
        setV2RayPingScanningIds({});
      }
    }
    return { completed: true, results: allResults };
  }

  async function pingV2RayProfiles(profiles: V2RayProfile[]) {
    await runV2RayProfileTests(profiles, backend.pingV2RayProfileIds, { clearExisting: true, kind: "ping" });
  }

  async function realDelayV2RayProfiles(profiles: V2RayProfile[]) {
    const requested = Array.from(new Map(profiles.filter((profile) => profile.id).map((profile) => [profile.id, profile])).values());
    if (!requested.length) {
      return;
    }
    const freshSpeedOK = new Set<string>();

    const speedRun = await runV2RayProfileTests(requested, backend.speedTestV2RayProfileIds, {
      batchSize: v2rayRuntimeTestBatchSize,
      clearExisting: true,
      kind: "speed",
    });
    if (!speedRun.completed) {
      return;
    }
    speedRun.results.forEach((result) => {
      if (result.speedOk) {
        freshSpeedOK.add(result.profileId);
      }
    });

    const delayProfiles = requested.filter((profile) => freshSpeedOK.has(profile.id));
    const skippedCount = requested.length - delayProfiles.length;
    if (!delayProfiles.length) {
      showError("No V2Ray profiles passed the speed test; real delay was not run.");
      return;
    }
    if (skippedCount > 0) {
      showSuccess(`Skipped ${skippedCount} V2Ray profile${skippedCount === 1 ? "" : "s"} whose speed test failed.`);
    }
    await runV2RayProfileTests(delayProfiles, backend.realDelayV2RayProfileIds, {
      batchSize: v2rayRuntimeTestBatchSize,
      kind: "delay",
    });
  }

  async function cancelV2RayProfileTests() {
    v2rayPingRunRef.current += 1;
    setV2RayPingRunning(false);
    setV2RayPingActiveKind("");
    setV2RayPingScanningIds({});
    try {
      await backend.cancelV2RayProfileTests();
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  async function run(action: () => Promise<AppState | ScannerState | string | void>) {
    clearErrorToast();
    try {
      const result = await action();
      if (typeof result === "object" && result && "connectionProfiles" in result) {
        applyState(result as AppState);
      } else if (typeof result === "object" && result && "validResolvers" in result) {
        setScannerState(result as ScannerState);
      }
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  async function openParallelConfigDialog() {
    if (!state || parallelTestState.status === "running") {
      return;
    }
    let options = parallelPresetOptions;
    if (options.length === 0) {
      try {
        options = await backend.getParallelTestPresetOptions();
        setParallelPresetOptions(options);
      } catch (err) {
        showError(messageFromError(err));
      }
    }
    const current = sanitizeParallelConfigSelection(parallelSelectedConfigIds, state, options);
    setParallelSelectedConfigIds(current.length ? current : defaultParallelConfigSelection(state, options));
    setParallelConfigDialogOpen(true);
  }

  async function startParallelTestWithSelection(ids: string[]) {
    clearErrorToast();
    try {
      const selected = state ? sanitizeParallelConfigSelection(ids, state, parallelPresetOptions) : ids;
      await backend.startParallelTest(selected);
      setParallelConfigDialogOpen(false);
    } catch (err) {
      showError(messageFromError(err));
    }
  }

  if (!state) {
    return (
      <>
        <LoadingView />
        <ErrorToast toast={errorToast} onDismiss={clearErrorToast} />
        <SuccessToast toast={successToast} onDismiss={clearSuccessToast} />
      </>
    );
  }

  const v2rayPing: V2RayPingState = {
    running: v2rayPingRunning,
    activeKind: v2rayPingActiveKind,
    results: v2rayPingResults,
    scanningIds: v2rayPingScanningIds,
    checkedAt: v2rayPingCheckedAt,
  };
  const activePage = page === "v2ray-dashboard" ? "v2ray-profiles" : page;

  return (
    <TooltipProvider>
      <SidebarProvider defaultOpen>
        <AppSidebar page={activePage} runtime={state.runtime} onPage={setPage} />
        <SidebarInset className="min-w-0 overflow-x-hidden">
          <main className="min-h-svh min-w-0 overflow-x-hidden bg-muted/30 p-4 md:p-6">
            <div className="mx-auto flex w-full min-w-0 max-w-7xl flex-col gap-4">
              <div className="flex items-center justify-between gap-2 md:hidden">
                <div className="flex min-w-0 items-center gap-2">
                  <SidebarTrigger />
                  <AppIcon className="size-7" />
                  <span className="min-w-0 truncate text-sm font-medium">WhiteDNS</span>
                </div>
                <ThemeSettingsMenu />
              </div>

              <ErrorToast toast={errorToast} onDismiss={clearErrorToast} />
              <SuccessToast toast={successToast} onDismiss={clearSuccessToast} />

              {activePage === "dashboard" && (
                <DashboardPage
                  state={state}
                  selectedConnection={selectedConnection}
                  selectedResolver={selectedResolver}
                  selectedSettings={selectedSettings}
                  parallelTest={parallelTestState}
                  scanner={scannerState}
                  validation={resolverValidation}
                  onNavigate={setPage}
                  onRun={run}
                  onToml={setToml}
                  onOpenParallelTest={openParallelConfigDialog}
                />
              )}

              {activePage === "connections" && (
                <ConnectionsPage state={state} onState={applyState} onError={showError} onSuccess={showSuccess} />
              )}

              {activePage === "whitedns-vpn" && (
                <WhiteDNSVPNPage state={state} onState={applyState} onError={showError} />
              )}

              {activePage === "whitedns-vpn-logs" && (
                <LogsPage
                  runtime={state.runtime}
                  runtimeType="v2ray"
                  title="WhiteDNS VPN Diagnostics"
                  description="WhiteDNS VPN runtime diagnostics."
                  onState={applyState}
                  onError={showError}
                />
              )}

              {activePage === "v2ray-profiles" && (
                <V2RayProfilesPage
                  state={state}
                  ping={v2rayPing}
                  onPingProfiles={pingV2RayProfiles}
                  onRealDelayProfiles={realDelayV2RayProfiles}
                  onCancelProfileTests={cancelV2RayProfileTests}
                  onForgetPingProfiles={forgetV2RayPingProfiles}
                  onState={applyState}
                  onError={showError}
                  onSuccess={showSuccess}
                />
              )}

              {activePage === "v2ray-subscriptions" && (
                <V2RaySubscriptionsPage
                  state={state}
                  ping={v2rayPing}
                  onForgetPingProfiles={forgetV2RayPingProfiles}
                  onState={applyState}
                  onError={showError}
                  onSuccess={showSuccess}
                />
              )}

              {activePage === "v2ray-settings" && (
                <V2RaySettingsPage state={state} onState={applyState} onError={showError} />
              )}

              {activePage === "v2ray-logs" && <LogsPage runtime={state.runtime} runtimeType="v2ray" onState={applyState} onError={showError} />}

              {activePage === "resolvers" && (
                <ResolversPage
                  state={state}
                  validation={resolverValidation}
                  onState={applyState}
                  onError={showError}
                />
              )}

              {activePage === "settings" && selectedSettings && (
                <SettingsPage
                  state={state}
                  section={settingsSection}
                  onSection={setSettingsSection}
                  onState={applyState}
                  onError={showError}
                  onSuccess={showSuccess}
                  onToml={setToml}
                />
              )}

              {activePage === "v2ray-white-ips" && (
                <V2RayWhiteIPsPage onState={applyState} onError={showError} onSuccess={showSuccess} />
              )}

              {activePage === "scanner" && (
                <ScannerPage state={state} scanner={scannerState} onState={setScannerState} onAppState={applyState} onError={showError} />
              )}

              {activePage === "validator" && (
                <ValidatorPage state={validatorState} onState={applyValidatorState} onAppState={applyState} onError={showError} />
              )}

              {activePage === "backup" && (
                <FullBackupPage state={state} onState={applyState} onError={showError} onSuccess={showSuccess} />
              )}

              {activePage === "logs" && <LogsPage runtime={state.runtime} runtimeType="masterdns" onState={applyState} onError={showError} />}
            </div>
          </main>
        </SidebarInset>

        <Dialog open={Boolean(toml)} onOpenChange={(open) => !open && setToml("")}>
          <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-3xl">
            <DialogHeader>
              <DialogTitle>client_config.toml</DialogTitle>
              <DialogDescription>Exported MasterDNS/StormDNS client configuration for the selected profiles.</DialogDescription>
            </DialogHeader>
            <Textarea
              readOnly
              value={toml}
              className="h-[min(58svh,32rem)] min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
            />
            <DialogFooter>
              <Button type="button" onClick={() => navigator.clipboard?.writeText(toml)}>
                <Copy />
                Copy TOML
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <ParallelTestConfigDialog
          open={parallelConfigDialogOpen}
          state={state}
          builtInOptions={parallelPresetOptions}
          selectedIds={parallelSelectedConfigIds}
          onOpenChange={setParallelConfigDialogOpen}
          onSelectedIds={setParallelSelectedConfigIds}
          onStart={startParallelTestWithSelection}
        />
      </SidebarProvider>
    </TooltipProvider>
  );
}

function ErrorToast({ toast, onDismiss }: { toast: AppErrorToast | null; onDismiss: () => void }) {
  if (!toast) {
    return null;
  }

  return (
    <div className="fixed top-4 right-4 left-4 z-50 sm:top-6 sm:right-6 sm:left-auto sm:w-full sm:max-w-md">
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
    <div className="fixed top-4 right-4 left-4 z-50 sm:top-6 sm:right-6 sm:left-auto sm:w-full sm:max-w-md">
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
          className="absolute right-0 top-[calc(100%+0.375rem)] z-50 w-52 overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md"
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
        "relative flex w-full items-center gap-2 rounded-sm py-1.5 pr-2 pl-8 text-left text-sm outline-none transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:bg-accent focus-visible:text-accent-foreground [&_svg]:size-4 [&_svg]:shrink-0",
        active && "bg-accent text-accent-foreground",
      )}
    >
      <span className="absolute left-2 flex size-3.5 items-center justify-center">
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
}: {
  page: Page;
  runtime: RuntimeStatus;
  onPage: (page: Page) => void;
}) {
  const sidebarEndpoint = runtimeProxyDisplayEndpoint(runtime);
  const [openGroups, setOpenGroups] = useState<Record<NavGroup["id"], boolean>>({
    masterdns: true,
    whitedns: true,
    v2ray: true,
    tools: true,
  });

  function toggleGroup(groupId: NavGroup["id"]) {
    setOpenGroups((current) => ({
      ...current,
      [groupId]: !current[groupId],
    }));
  }

  return (
    <Sidebar collapsible="icon" variant="sidebar">
      <SidebarHeader>
        <div className="flex items-center justify-between gap-2 px-2 py-2">
          <div className="flex min-w-0 items-center gap-2.5">
            <div className="grid size-9 shrink-0 place-items-center overflow-hidden rounded-lg border bg-background">
              <AppIcon className="size-8" />
            </div>
            <div className="min-w-0 group-data-[collapsible=icon]:hidden">
              <div className="truncate text-sm leading-snug font-medium">WhiteDNS</div>
              <p className="truncate text-sm leading-normal text-muted-foreground">v1.0.0-beta6</p>
            </div>
          </div>
          <ThemeSettingsMenu
            sidebar
            className="ml-auto group-data-[collapsible=icon]:hidden"
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
          <span className="truncate">Source: WhiteDNS Telegram</span>
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
                      <span className="truncate">{group.label}</span>
                      {isOpen ? (
                        <ChevronDown className="ml-auto size-3.5 shrink-0" aria-hidden="true" />
                      ) : (
                        <ChevronRight className="ml-auto size-3.5 shrink-0" aria-hidden="true" />
                      )}
                    </button>
                  </SidebarGroupLabel>

                  {isOpen && (
                    <SidebarMenu className="mt-1">
                      {group.items.map((item) => (
                        <SidebarMenuItem key={item.id}>
                          <SidebarMenuButton
                            isActive={page === item.id}
                            tooltip={item.label}
                            onClick={() => onPage(item.id)}
                          >
                            {item.icon}
                            <span>{item.label}</span>
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
            <ItemTitle>{statusLabel(runtime.status)}</ItemTitle>
            <ItemDescription className="line-clamp-none">
              <span className="block">
                {sidebarEndpoint || "No active proxy"}
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

function LoadingView() {
  return (
    <main className="grid min-h-svh place-items-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>WhiteDNS Desktop</CardTitle>
          <CardDescription>Loading command center</CardDescription>
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

function DashboardPage({
  state,
  selectedConnection,
  selectedResolver,
  selectedSettings,
  parallelTest,
  scanner,
  validation,
  onNavigate,
  onRun,
  onToml,
  onOpenParallelTest,
}: {
  state: AppState;
  selectedConnection?: ConnectionProfile;
  selectedResolver?: ResolverProfile;
  selectedSettings?: SettingsProfile;
  parallelTest: ParallelTestState;
  scanner: ScannerState;
  validation: ResolverTextValidation;
  onNavigate: (page: Page) => void;
  onRun: (action: () => Promise<AppState | ScannerState | string | void>) => Promise<void>;
  onToml: (toml: string) => void;
  onOpenParallelTest: () => void;
}) {
  const runtime = state.runtime;
  const canStart = runtime.status === "disconnected" || runtime.status === "failed";
  const masterRuntimeActive = masterDNSRuntimeActive(state);
  const otherRuntimeBusy = !masterRuntimeActive && runtime.status !== "disconnected" && runtime.status !== "failed";
  const isConnected = runtime.status === "connected" && masterRuntimeActive;
  const isConnecting = runtime.status === "connecting" && masterRuntimeActive;
  const parallelRunning = parallelTest.status === "running";
  const parallelFailed = parallelTest.status === "failed";
  const parallelVisible = parallelRunning || parallelFailed;
  const upgradeScannerVisible = scanner.mode === "connection-upgrade" && (scanner.status === "running" || scanner.restartAvailable);
  const upgradeScannerProgress = scanner.total > 0 ? Math.round((scanner.completed / scanner.total) * 100) : 0;
  const isLocked = (runtime.status !== "disconnected" && runtime.status !== "failed") || parallelRunning;
  const [resolverCopyDialog, setResolverCopyDialog] = useState<ResolverCopyDialogState | null>(null);
  const [resolverCopyStatus, setResolverCopyStatus] = useState("");
  const [cloudflarePing, setCloudflarePing] = useState<CloudflarePingResult | null>(null);
  const [cloudflarePingRunning, setCloudflarePingRunning] = useState(false);
  const [proxyCountryLookup, setProxyCountryLookup] = useState<ProxyCountryLookupResult | null>(null);
  const [proxyCountryLookupRunning, setProxyCountryLookupRunning] = useState(false);
  const proxyCountryLookupKeyRef = useRef("");
  const missingConnection = !otherRuntimeBusy && (!selectedConnection?.domain.trim() || !selectedConnection?.encryptionKey.trim());
  const configuredResolverCount = resolverProfileCount(selectedResolver, validation);
  const missingResolvers = !otherRuntimeBusy && (configuredResolverCount <= 0 || (!isFileBackedResolver(selectedResolver) && !validation.isValid));
  const connectDisabled = otherRuntimeBusy || parallelRunning || (canStart && (missingConnection || missingResolvers));
  const connectionActionLabel = isConnected ? "Disconnect" : isConnecting ? "Cancel" : parallelRunning ? "Testing" : "Connect";
  const progress = runtime.progress;
  const showStartupProgress = isConnecting;
  const runtimeEndpoint = proxyEndpoint(runtime.listenIp, runtime.listenPort);
  const selectedSettingsEndpoint = selectedSettings ? proxyEndpoint(selectedSettings.listenIp, selectedSettings.listenPort) : "";
  const endpoint = runtimeEndpoint || selectedSettingsEndpoint || "-";
  const localProxyEndpoint = proxyEndpoint(runtime.localProxyIp, runtime.listenPort);
  const publicProxyEndpoint = localProxyEndpoint
    ? proxyEndpoint(runtime.publicProxyIp, runtime.listenPort) || "Not available"
    : "";
  const proxyCountryLookupKey =
    isConnected && runtime.listenPort > 0
      ? [
          runtime.activeConnectionId,
          runtime.listenIp,
          runtime.localProxyIp,
          runtime.listenPort,
        ].join("|")
      : "";
  const hasShareProxyMetrics = Boolean(localProxyEndpoint);
  const statusEndpoint = hasShareProxyMetrics && publicProxyEndpoint !== "Not available"
    ? publicProxyEndpoint
    : localProxyEndpoint || endpoint;
  const proxyCountry = proxyCountryInfo(
    selectedConnection,
    selectedSettings,
    runtime,
    proxyCountryLookup,
    proxyCountryLookupRunning
  );
  const dashboardStatus = parallelRunning ? "parallel-testing" : parallelFailed ? "failed" : masterRuntimeActive ? runtime.status : "disconnected";
  const dashboardTitle = parallelRunning
    ? "Testing"
    : parallelFailed
      ? "Parallel test failed"
      : otherRuntimeBusy
        ? "Another runtime is active"
        : runtime.message || "Ready";
  const dashboardDescription = parallelRunning
    ? parallelTest.message || "Parallel Testing"
    : parallelFailed
      ? parallelTest.error || parallelTest.message || "Parallel test failed"
    : otherRuntimeBusy
      ? "V2Ray is connected. Use the V2Ray dashboard to manage it."
    : isConnected
      ? `Proxy listening on ${statusEndpoint}`
      : masterRuntimeActive && runtime.status === "failed"
        ? "Connection failed"
        : !masterRuntimeActive || runtime.status === "disconnected"
          ? "Runtime idle"
          : progressLabel(progress.phase, progress.percent);
  const autoProfileName = runtime.autoProfileName.trim();
  const autoProfilePresetId = runtime.autoProfilePresetId.trim();
  const autoProfileSaved = autoProfileName
    ? state.settingsProfiles.some((profile) => settingsProfileNameKey(profile.name) === settingsProfileNameKey(autoProfileName))
    : false;
  const resolverHealthLive = masterRuntimeActive && (isConnected || isConnecting);
  const activeResolverSource = resolverHealthLive ? runtime.resolverState.activeResolvers || [] : [];
  const validResolverSource = resolverHealthLive ? runtime.resolverState.validResolvers || [] : [];
  const standbyResolverSource = resolverHealthLive ? runtime.resolverState.standbyResolvers || [] : [];
  const resolverDetailSource = resolverHealthLive ? runtime.resolverState.resolverDetails || [] : [];
  const activeResolverCount = resolverHealthLive ? resolverRuntimeCount(activeResolverSource, runtime.resolverState.activeCount) : 0;
  const validResolverCount = resolverHealthLive ? resolverRuntimeCount(validResolverSource, runtime.resolverState.validCount) : 0;
  const standbyResolverCount = resolverHealthLive ? resolverRuntimeCount(standbyResolverSource, runtime.resolverState.standbyCount) : 0;
  const rejectedResolverCount = resolverHealthLive ? liveRejectedResolverCount(runtime) : 0;
  const activeResolversComplete = resolverRuntimeComplete(activeResolverSource, runtime.resolverState.activeCount, runtime.resolverState.activeComplete);
  const validResolversComplete = resolverRuntimeComplete(validResolverSource, runtime.resolverState.validCount, runtime.resolverState.validComplete);
  const mtuResolverFailureWarning = getMTUResolverFailureWarning(runtime);

  function openResolverCopyDialog(kind: "active" | "valid", resolvers: string[], totalCount: number, complete: boolean) {
    if (!resolvers.length) {
      return;
    }
    const label = kind === "active" ? "active" : "valid";
    const count = totalCount || resolvers.length;
    setResolverCopyStatus("");
    setResolverCopyDialog({
      title: kind === "active" ? "Active resolvers" : "Valid resolvers",
      description: complete
        ? `${count} ${label} resolver${count === 1 ? "" : "s"} ready to copy.`
        : `Showing ${resolvers.length} of ${count} ${label} resolvers from the latest runtime snapshot.`,
      copyLabel: `Copy all ${label}`,
      resolvers,
      resolverDetails: resolverDialogDetails(kind, resolvers, resolverDetailSource),
    });
  }

  async function copyResolverDialogText() {
    if (!resolverCopyDialog?.resolvers.length) {
      return;
    }
    try {
      await navigator.clipboard?.writeText(resolverCopyDialog.resolvers.join("\n"));
      setResolverCopyStatus("Copied");
    } catch {
      setResolverCopyStatus("Copy failed");
    }
  }

  async function pingCloudflare() {
    setCloudflarePingRunning(true);
    setCloudflarePing(null);
    try {
      setCloudflarePing(await backend.pingCloudflare());
    } catch (err) {
      setCloudflarePing({
        ok: false,
        target: "https://www.google.com/generate_204",
        proxy: statusEndpoint || endpoint,
        latencyMs: 0,
        message: messageFromError(err),
      });
    } finally {
      setCloudflarePingRunning(false);
    }
  }

  useEffect(() => {
    if (!isConnected || runtime.listenPort <= 0 || !proxyCountryLookupKey) {
      proxyCountryLookupKeyRef.current = "";
      setProxyCountryLookup(null);
      setProxyCountryLookupRunning(false);
      return;
    }
    if (proxyCountryLookupKeyRef.current === proxyCountryLookupKey) {
      return;
    }

    let cancelled = false;
    proxyCountryLookupKeyRef.current = proxyCountryLookupKey;
    setProxyCountryLookup(null);
    setProxyCountryLookupRunning(true);
    backend
      .lookupProxyCountry()
      .then((result) => {
        if (!cancelled) {
          setProxyCountryLookup(result);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setProxyCountryLookup({
            ok: false,
            ip: "",
            countryCode: "",
            proxy: statusEndpoint || endpoint,
            message: messageFromError(err),
          });
        }
      })
      .finally(() => {
        if (!cancelled) {
          setProxyCountryLookupRunning(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [
    isConnected,
    runtime.listenPort,
    proxyCountryLookupKey,
  ]);

  useEffect(() => {
    if (!isConnected) {
      setResolverCopyDialog(null);
      setResolverCopyStatus("");
      setCloudflarePing(null);
    }
  }, [isConnected]);

  return (
    <PageShell
      eyebrow="Dashboard"
      title="Command Center"
      actions={
        <>
          <Button
            variant="outline"
            onClick={() =>
              onRun(async () => {
                const exported = await backend.exportClientToml();
                onToml(exported);
              })
            }
          >
            <FileText />
            Export TOML
          </Button>
          <Button variant="destructive" onClick={() => backend.quit()}>
            <X />
            Quit
          </Button>
        </>
      }
    >
      <Card className={cn("relative overflow-hidden transition-all duration-500 border-2", statusCardTone(dashboardStatus))}>
        {/* Animated gradient overlay on connected state */}
        {isConnected && (
          <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/5 via-emerald-500/10 to-emerald-500/5 animate-pulse-slow" />
        )}
        <CardContent className="relative z-10 flex flex-col gap-3 p-6">
          <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div className="flex min-w-0 items-start gap-4">
                {/* Large status indicator with glow */}
                <div className={cn(
                  "flex items-center justify-center shrink-0 rounded-full w-14 h-14 transition-all duration-300",
                  isConnected && "ring-4 ring-emerald-500/20 shadow-[0_0_20px_rgba(16,185,129,0.3)]"
                )}>
                  <StatusDot status={dashboardStatus} className="size-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <Badge variant={statusBadgeVariant(dashboardStatus)} className="h-6 px-3 font-medium">
                      {statusLabel(dashboardStatus)}
                    </Badge>
                    {runtime.activeConnectionId && <Badge variant="outline" className="h-6 px-3">Active route</Badge>}
                  </div>
                  <h2 className="text-2xl font-bold tracking-tight animate-in">
                    {dashboardTitle}
                  </h2>
                  <p className="mt-2 text-sm text-muted-foreground">{dashboardDescription}</p>
                  {isConnected && autoProfileName && (
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
                      <span className="text-muted-foreground">Connected to auto profile</span>
                      <Badge variant="secondary">{autoProfileName}</Badge>
                      {!autoProfileSaved && autoProfilePresetId && (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => onRun(() => backend.saveParallelTestPresets([autoProfilePresetId]))}
                        >
                          <Save />
                          Save
                        </Button>
                      )}
                    </div>
                  )}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:justify-end">
                {otherRuntimeBusy ? (
                  <Button size="default" variant="outline" className="min-w-36" disabled>
                    <Shield />
                    V2Ray active
                  </Button>
                ) : canStart ? (
                  <ConnectActionButtons
                    disabled={connectDisabled}
                    parallelDisabled={connectDisabled}
                    parallelRunning={parallelRunning}
                    status={runtime.status}
                    label={connectionActionLabel}
                    onConnect={() => onRun(() => backend.startConnection())}
                    onParallelTest={onOpenParallelTest}
                    onCancelParallelTest={() => onRun(async () => { await backend.cancelParallelTest(); })}
                  />
                ) : (
                  <Button
                    size="lg"
                    variant="outline"
                    className={cn(
                      "h-11 min-w-36 px-6 font-semibold transition-all duration-300",
                      statusButtonTone(runtime.status)
                    )}
                    disabled={connectDisabled}
                    onClick={() => onRun(() => backend.stopConnection())}
                  >
                    {isConnected ? <Square className="size-5" /> : isConnecting ? <X className="size-5" /> : <Power className="size-5" />}
                    {connectionActionLabel}
                  </Button>
                )}
              </div>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-lg border-2 bg-card p-4">
              <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Connection
              </label>
              <DashboardSelector
                label=""
                value={selectedConnection?.id || state.selectedConnectionProfileId}
                detail=""
                disabled={isLocked}
                items={state.connectionProfiles.map((profile) => ({
                  id: profile.id,
                  title: profile.name,
                }))}
                onChange={(id) => onRun(() => backend.selectConnectionProfile(id))}
              />
              <p className="mt-2 text-xs text-muted-foreground truncate">
                {selectedConnection?.domain || "No domain"}
              </p>
            </div>

            <div className="rounded-lg border-2 bg-card p-4">
              <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Resolver
              </label>
              <DashboardSelector
                label=""
                value={selectedResolver?.id || state.selectedResolverProfileId}
                detail=""
                disabled={isLocked}
                items={state.resolverProfiles.map((profile) => ({
                  id: profile.id,
                  title: profile.name,
                }))}
                onChange={(id) => onRun(() => backend.selectResolverProfile(id))}
              />
              <p className="mt-2 text-xs text-muted-foreground">
                {configuredResolverCount} configured
              </p>
            </div>

            <div className="rounded-lg border-2 bg-card p-4">
              <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Settings
              </label>
              <DashboardSelector
                label=""
                value={state.selectedSettingsProfileId}
                detail=""
                disabled={isLocked}
                items={state.settingsProfiles.map((profile) => ({
                  id: profile.id,
                  title: profile.name,
                }))}
                onChange={(id) => onRun(() => backend.selectSettingsProfile(id))}
              />
              <p className="mt-2 text-xs font-mono text-muted-foreground">
                {selectedSettings ? `${selectedSettings.listenIp}:${selectedSettings.listenPort}` : "No proxy"}
              </p>
            </div>
          </div>

          {parallelVisible && (
            <ParallelTestPanel
              state={parallelTest}
            />
          )}

          {mtuResolverFailureWarning && (
            <Alert className="border-amber-200 bg-amber-50/95 text-amber-950">
              <AlertCircle />
              <AlertTitle>{mtuResolverFailureWarning.title}</AlertTitle>
              <AlertDescription>{mtuResolverFailureWarning.description}</AlertDescription>
            </Alert>
          )}

          <div className="rounded-lg border bg-background/60 p-3">
            {showStartupProgress ? (
              <StartupProgressMini progress={progress} />
            ) : otherRuntimeBusy ? (
              <div>
                <h3 className="text-sm font-medium">MasterDNS idle</h3>
                <p className="mt-1 text-xs text-muted-foreground">V2Ray is using the shared runtime right now.</p>
              </div>
            ) : runtime.status === "failed" ? (
              <div className="flex items-start gap-3">
                <AlertCircle className="mt-0.5 size-4 shrink-0 text-destructive" />
                <div className="min-w-0">
                  <h3 className="text-sm font-medium">Startup failed</h3>
                  <p className="mt-1 break-words text-xs text-muted-foreground">
                    {runtime.message || "Connection failed before the proxy became ready."}
                  </p>
                </div>
              </div>
            ) : runtime.status === "disconnected" ? (
              <div>
                <h3 className="text-sm font-medium">Runtime idle</h3>
                <p className="mt-1 text-xs text-muted-foreground">Proxy is not running.</p>
              </div>
            ) : (
              <ConnectionInfoBar
                proxyCountry={proxyCountry}
                proxyEndpoint={statusEndpoint || endpoint}
                download={formatSpeed(runtime.stats.downloadSpeedBytesPerSecond)}
                upload={formatSpeed(runtime.stats.uploadSpeedBytesPerSecond)}
                received={formatBytes(runtime.stats.totalDataUsageBytes)}
                trafficMonitorMessage={runtime.trafficMonitorMessage}
                ping={cloudflarePing}
                pingRunning={cloudflarePingRunning}
                onPing={pingCloudflare}
              />
            )}
          </div>
        </CardContent>
      </Card>

      {(missingConnection || missingResolvers) && (
        <Alert className="border-amber-200 bg-amber-50 text-amber-950">
          <AlertCircle />
          <AlertTitle>Setup required</AlertTitle>
          <AlertDescription>
            {missingConnection
              ? "Connection profile needs a MasterDNS/StormDNS domain and encryption key."
              : "Resolver profile needs at least one valid resolver."}
          </AlertDescription>
          <AlertAction>
            <Button variant="outline" size="sm" onClick={() => onNavigate(missingConnection ? "connections" : "resolvers")}>
              Fix
            </Button>
          </AlertAction>
        </Alert>
      )}

      <Card className="overflow-hidden border-2">
        <CardContent className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold">Resolver Health</h3>
              <p className="text-xs text-muted-foreground">
                {isConnecting ? progressSummary(progress) : resolverHealthLive ? "Live pool" : "Idle"}
              </p>
            </div>
            {/* Mini chart showing distribution */}
            <div className="flex gap-1">
              {[
                { count: activeResolverCount, color: "rgb(16, 185, 129)" },
                { count: validResolverCount, color: "rgb(14, 165, 233)" },
                { count: standbyResolverCount, color: "rgb(245, 158, 11)" },
                { count: rejectedResolverCount, color: "rgb(239, 68, 68)" },
              ].map((item, i) => {
                const maxCount = Math.max(activeResolverCount, validResolverCount, standbyResolverCount, rejectedResolverCount, 1);
                const height = (item.count / maxCount) * 32;
                return (
                  <div
                    key={i}
                    className="w-1.5 rounded-full transition-all duration-500"
                    style={{
                      height: `${Math.max(height, 4)}px`,
                      backgroundColor: item.color,
                      opacity: item.count > 0 ? 1 : 0.3
                    }}
                  />
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {/* Active */}
            <button
              onClick={
                activeResolverSource.length
                  ? () =>
                      openResolverCopyDialog(
                        "active",
                        activeResolverSource,
                        activeResolverCount || activeResolverSource.length,
                        activeResolversComplete
                      )
                  : undefined
              }
              disabled={!activeResolverSource.length}
              className={cn(
                "group relative overflow-hidden rounded-lg border-2 border-emerald-500/30 bg-emerald-500/5 p-4 transition-all duration-300 text-left",
                activeResolverSource.length && "hover:border-emerald-500 hover:shadow-[0_0_20px_rgba(16,185,129,0.15)] cursor-pointer"
              )}
            >
              <div className="flex items-center gap-3">
                <div className="relative shrink-0">
                  <svg className="size-10 -rotate-90">
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-emerald-500/20"
                    />
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-emerald-500 transition-all duration-500"
                      strokeDasharray={`${(activeResolverCount / Math.max(configuredResolverCount, 1)) * 100} 100`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="size-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]" />
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium uppercase tracking-wider text-emerald-700 dark:text-emerald-400">
                    Active
                  </p>
                  <p className="text-2xl font-bold text-emerald-600 tabular-nums">
                    {activeResolverCount}
                  </p>
                </div>
              </div>
            </button>

            {/* Valid */}
            <button
              onClick={
                validResolverSource.length
                  ? () => openResolverCopyDialog("valid", validResolverSource, validResolverCount, validResolversComplete)
                  : undefined
              }
              disabled={!validResolverSource.length}
              className={cn(
                "group relative overflow-hidden rounded-lg border-2 border-sky-500/30 bg-sky-500/5 p-4 transition-all duration-300 text-left",
                validResolverSource.length && "hover:border-sky-500 hover:shadow-[0_0_20px_rgba(14,165,233,0.15)] cursor-pointer"
              )}
            >
              <div className="flex items-center gap-3">
                <div className="relative shrink-0">
                  <svg className="size-10 -rotate-90">
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-sky-500/20"
                    />
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-sky-500 transition-all duration-500"
                      strokeDasharray={`${(validResolverCount / Math.max(configuredResolverCount, 1)) * 100} 100`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="size-2 rounded-full bg-sky-500 shadow-[0_0_8px_rgba(14,165,233,0.6)]" />
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium uppercase tracking-wider text-sky-700 dark:text-sky-400">
                    Valid
                  </p>
                  <p className="text-2xl font-bold text-sky-600 tabular-nums">
                    {validResolverCount}
                  </p>
                </div>
              </div>
            </button>

            {/* Standby */}
            <div className="group relative overflow-hidden rounded-lg border-2 border-amber-500/30 bg-amber-500/5 p-4 transition-all duration-300">
              <div className="flex items-center gap-3">
                <div className="relative shrink-0">
                  <svg className="size-10 -rotate-90">
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-amber-500/20"
                    />
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-amber-500 transition-all duration-500"
                      strokeDasharray={`${(standbyResolverCount / Math.max(configuredResolverCount, 1)) * 100} 100`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="size-2 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.6)]" />
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium uppercase tracking-wider text-amber-700 dark:text-amber-400">
                    Standby
                  </p>
                  <p className="text-2xl font-bold text-amber-600 tabular-nums">
                    {standbyResolverCount}
                  </p>
                </div>
              </div>
            </div>

            {/* Rejected */}
            <div className="group relative overflow-hidden rounded-lg border-2 border-red-500/30 bg-red-500/5 p-4 transition-all duration-300">
              <div className="flex items-center gap-3">
                <div className="relative shrink-0">
                  <svg className="size-10 -rotate-90">
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-red-500/20"
                    />
                    <circle
                      cx="20"
                      cy="20"
                      r="16"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="3"
                      className="text-red-500 transition-all duration-500"
                      strokeDasharray={`${(rejectedResolverCount / Math.max(configuredResolverCount, 1)) * 100} 100`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="size-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]" />
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium uppercase tracking-wider text-red-700 dark:text-red-400">
                    Rejected
                  </p>
                  <p className="text-2xl font-bold text-red-600 tabular-nums">
                    {rejectedResolverCount}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Progress bar during connection */}
          {isConnecting && runtime.progress.phase && (
            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">{runtime.progress.phase}</span>
                <span className="tabular-nums">{runtime.progress.percent}%</span>
              </div>
              <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full bg-emerald-500 transition-all duration-300"
                  style={{ width: `${runtime.progress.percent}%` }}
                />
              </div>
            </div>
          )}

          {/* Save Valids Button */}
          {isConnected && validResolverSource.length > 0 && (
            <div className="flex justify-end mt-4">
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={!validResolversComplete}
                onClick={() =>
                  onRun(() =>
                    backend.saveResolverProfileSnapshot({
                      id: "",
                      name: `${selectedResolver?.name || "Resolvers"} valid`,
                      resolverText: validResolverSource.join("\n"),
                    })
                  )
                }
              >
                <ListChecks />
                Save Valids
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {upgradeScannerVisible && (
        <ConnectionUpgradeScannerPanel
          scanner={scanner}
          progress={upgradeScannerProgress}
          onSaveRestart={() => onRun(() => backend.applyScannerConnectionUpgrade("save"))}
          onRuntimeRestart={() => onRun(() => backend.applyScannerConnectionUpgrade("runtime"))}
          onKeepCurrent={() => onRun(() => backend.dismissScannerConnectionUpgrade())}
        />
      )}
      <ResolverListDialog
        open={Boolean(resolverCopyDialog)}
        title={resolverCopyDialog?.title || ""}
        description={resolverCopyDialog?.description || ""}
        copyLabel={resolverCopyDialog?.copyLabel || "Copy"}
        resolvers={resolverCopyDialog?.resolvers || []}
        resolverDetails={resolverCopyDialog?.resolverDetails || []}
        copyStatus={resolverCopyStatus}
        onCopy={copyResolverDialogText}
        onOpenChange={(open) => {
          if (!open) {
            setResolverCopyDialog(null);
            setResolverCopyStatus("");
          }
        }}
      />
    </PageShell>
  );
}

function ConnectionInfoBar({
  proxyCountry,
  proxyEndpoint,
  download,
  upload,
  received,
  trafficMonitorMessage,
  ping,
  pingRunning,
  onPing,
}: {
  proxyCountry: ProxyCountryInfo;
  proxyEndpoint: string;
  download: string;
  upload: string;
  received: string;
  trafficMonitorMessage: string;
  ping: CloudflarePingResult | null;
  pingRunning: boolean;
  onPing: () => void;
}) {
  const pingLabel = pingRunning ? "Pinging..." : ping?.ok ? `${ping.latencyMs} ms` : "Ping Google";

  return (
    <div className="space-y-3">
      <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-5">
        {/* Country */}
        <div className="rounded-lg border bg-card p-3 transition-all duration-300 hover:border-muted-foreground/30">
          <div className="flex items-center gap-2.5">
            <div className="rounded-full bg-muted/50 p-1.5 shrink-0">
              {proxyCountry.icon && <span className="text-xl leading-none">{proxyCountry.icon}</span>}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Location
              </p>
              <p className="mt-0.5 text-sm font-semibold truncate">
                {proxyCountry.name || "Detecting..."}
              </p>
            </div>
          </div>
        </div>

        {/* Endpoint */}
        <div className="rounded-lg border bg-card p-3 transition-all duration-300 hover:border-muted-foreground/30">
          <div className="flex items-center gap-2.5">
            <div className="rounded-full bg-muted/50 p-1.5 shrink-0">
              <Globe2 className="size-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Endpoint
              </p>
              <p className="mt-0.5 font-mono text-xs font-semibold truncate">
                {proxyEndpoint || "-"}
              </p>
            </div>
          </div>
        </div>

        {/* Download Speed */}
        <div className="rounded-lg border bg-card p-3 transition-all duration-300 hover:border-muted-foreground/30">
          <div className="flex items-center gap-2.5">
            <div className="rounded-full bg-muted/50 p-1.5 shrink-0">
              <Download className="size-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Download
              </p>
              <p className="mt-0.5 text-sm font-bold tabular-nums">
                {download}
              </p>
            </div>
          </div>
        </div>

        {/* Upload Speed */}
        <div className="rounded-lg border bg-card p-3 transition-all duration-300 hover:border-muted-foreground/30">
          <div className="flex items-center gap-2.5">
            <div className="rounded-full bg-muted/50 p-1.5 shrink-0">
              <Upload className="size-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Upload
              </p>
              <p className="mt-0.5 text-sm font-bold tabular-nums">
                {upload}
              </p>
            </div>
          </div>
        </div>

        {/* Total Data */}
        <div className="rounded-lg border bg-card p-3 transition-all duration-300 hover:border-muted-foreground/30">
          <div className="flex items-center gap-2.5">
            <div className="rounded-full bg-muted/50 p-1.5 shrink-0">
              <Activity className="size-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Total Data
              </p>
              <p className="mt-0.5 text-sm font-bold tabular-nums">
                {received}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Ping Button Row */}
      <div className="flex items-center justify-end">
        <Button type="button" variant="outline" size="sm" disabled={pingRunning} onClick={onPing}>
          <Gauge />
          {pingLabel}
        </Button>
      </div>

      {/* Messages */}
      {(ping || trafficMonitorMessage) && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          {ping && (
            <span className={cn("inline-flex items-center gap-1.5", ping.ok ? "text-emerald-700" : "text-destructive")}>
              {ping.ok ? <CheckCircle2 className="size-3.5" /> : <AlertCircle className="size-3.5" />}
              {ping.message}
            </span>
          )}
          {trafficMonitorMessage && (
            <span className="inline-flex items-center gap-1.5">
              <AlertCircle className="size-3.5" />
              Traffic monitor: {trafficMonitorMessage}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function ConnectionMetric({
  label,
  value,
  prefix,
  mono,
}: {
  label: string;
  value: string;
  prefix?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] font-medium text-muted-foreground">{label}</p>
      <p className={cn("mt-0.5 flex min-w-0 items-center gap-1.5 truncate text-sm font-semibold tracking-tight", mono && "font-mono text-xs")}>
        {prefix}
        <span className="truncate">{value}</span>
      </p>
    </div>
  );
}

function ConnectActionButtons({
  disabled,
  parallelDisabled,
  parallelRunning,
  status,
  label,
  onConnect,
  onParallelTest,
  onCancelParallelTest,
}: {
  disabled: boolean;
  parallelDisabled: boolean;
  parallelRunning: boolean;
  status: RuntimeStatusName;
  label: string;
  onConnect: () => void;
  onParallelTest: () => void;
  onCancelParallelTest: () => void;
}) {
  const secondaryLabel = parallelRunning ? "Cancel" : "Parallel test";
  const secondaryDescription = parallelRunning
    ? "Stop the current parallel test."
    : "Choose saved and built-in configs, then test them in parallel.";

  return (
    <div className="inline-flex items-center gap-2 whitespace-nowrap">
      <Button
        size="lg"
        variant="outline"
        className={cn(
          "h-11 min-w-[6.75rem] px-6 font-semibold transition-all duration-300",
          statusButtonTone(status),
          status === "disconnected" && !disabled && [
            "bg-emerald-600 text-white hover:bg-emerald-700 border-emerald-600",
            "shadow-[0_0_20px_rgba(16,185,129,0.25)]",
            "hover:shadow-[0_0_30px_rgba(16,185,129,0.4)]",
          ]
        )}
        disabled={disabled}
        onClick={onConnect}
      >
        <Power className="size-5" />
        {label}
      </Button>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            size="lg"
            variant={parallelRunning ? "outline" : "secondary"}
            className={cn(
              "h-11 min-w-[8.75rem] px-6 font-semibold transition-all duration-300",
              parallelRunning && "border-emerald-500 text-emerald-600"
            )}
            disabled={!parallelRunning && parallelDisabled}
            onClick={parallelRunning ? onCancelParallelTest : onParallelTest}
          >
            {parallelRunning ? <X className="size-5" /> : <Activity className={cn("size-5", parallelRunning && "animate-pulse")} />}
            {secondaryLabel}
          </Button>
        </TooltipTrigger>
        <TooltipContent
          side="bottom"
          align="end"
          className="max-w-72 text-xs leading-relaxed"
        >
          {secondaryDescription}
        </TooltipContent>
      </Tooltip>
    </div>
  );
}

function ParallelTestConfigDialog({
  open,
  state,
  builtInOptions,
  selectedIds,
  onOpenChange,
  onSelectedIds,
  onStart,
}: {
  open: boolean;
  state: AppState;
  builtInOptions: ParallelTestPresetOption[];
  selectedIds: string[];
  onOpenChange: (open: boolean) => void;
  onSelectedIds: (ids: string[]) => void;
  onStart: (ids: string[]) => Promise<void>;
}) {
  const allIds = [
    ...state.settingsProfiles.map((profile) => settingsSelectionId(profile.id)),
    ...builtInOptions.map((option) => builtinSelectionId(option.id)),
  ];
  const selected = new Set(selectedIds.filter((id) => allIds.includes(id)));
  const selectedCount = selected.size;
  const currentSettingsId = settingsSelectionId(state.selectedSettingsProfileId);
  const stableBuiltIns = builtInOptions.filter((option) => option.category === "Stable");
  const aggressiveBuiltIns = builtInOptions.filter((option) => option.category === "Aggressive");

  function toggle(id: string, checked: boolean) {
    const next = new Set(selected);
    if (checked) {
      next.add(id);
    } else {
      next.delete(id);
    }
    onSelectedIds(allIds.filter((candidate) => next.has(candidate)));
  }

  function selectRecommended() {
    onSelectedIds(defaultParallelConfigSelection(state, builtInOptions));
  }

  function selectAll() {
    onSelectedIds(allIds);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>Parallel test configs</DialogTitle>
          <DialogDescription>
            Choose saved settings and built-in auto-tune configs to compare with one shared resolver set.
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 space-y-3 overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border bg-muted/30 px-3 py-2">
            <div className="text-sm">
              <span className="font-medium">{selectedCount}</span>
              <span className="text-muted-foreground"> selected</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" size="sm" onClick={selectRecommended}>
                Recommended
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={selectAll}>
                Select all
              </Button>
              <Button type="button" variant="ghost" size="sm" onClick={() => onSelectedIds([])}>
                Clear
              </Button>
            </div>
          </div>

          <ScrollArea className="h-[min(58svh,31rem)] pr-3">
            <div className="grid gap-4 lg:grid-cols-2">
              <section className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-medium">Your settings</h3>
                  <Badge variant="outline">{state.settingsProfiles.length}</Badge>
                </div>
                <div className="grid gap-2">
                  {state.settingsProfiles.map((profile) => {
                    const id = settingsSelectionId(profile.id);
                    return (
                      <ParallelConfigOptionRow
                        key={id}
                        title={profile.name}
                        detail={`${profile.listenIp}:${profile.listenPort} · U ${profile.minUploadMtu}-${profile.maxUploadMtu} · D ${profile.minDownloadMtu}-${profile.maxDownloadMtu}`}
                        badges={id === currentSettingsId ? ["Current"] : []}
                        checked={selected.has(id)}
                        onCheckedChange={(checked) => toggle(id, checked)}
                      />
                    );
                  })}
                </div>
              </section>

              <section className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-medium">Built-in auto-tune</h3>
                  <Badge variant="outline">{builtInOptions.length}</Badge>
                </div>
                {[
                  ["Stable", stableBuiltIns] as const,
                  ["Aggressive", aggressiveBuiltIns] as const,
                ].map(([category, options]) => (
                  options.length > 0 && (
                    <div key={category} className="space-y-2">
                      <Badge variant="secondary">{category}</Badge>
                      <div className="grid gap-2">
                        {options.map((option) => {
                          const id = builtinSelectionId(option.id);
                          return (
                            <ParallelConfigOptionRow
                              key={id}
                              title={option.name}
                              detail={`U ${option.settings.minUploadMtu}-${option.settings.maxUploadMtu} · D ${option.settings.minDownloadMtu}-${option.settings.maxDownloadMtu} · dup ${option.settings.uploadDuplication}/${option.settings.downloadDuplication}`}
                              badges={option.saved ? ["Saved"] : []}
                              checked={selected.has(id)}
                              onCheckedChange={(checked) => toggle(id, checked)}
                            />
                          );
                        })}
                      </div>
                    </div>
                  )
                ))}
              </section>
            </div>
            <ScrollBar />
          </ScrollArea>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button type="button" disabled={selectedCount < 2} onClick={() => onStart(allIds.filter((id) => selected.has(id)))}>
            <Activity />
            Start parallel test
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ParallelConfigOptionRow({
  title,
  detail,
  badges,
  checked,
  onCheckedChange,
}: {
  title: string;
  detail: string;
  badges: string[];
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className={cn("flex min-w-0 items-center justify-between gap-3 rounded-lg border bg-background/70 px-3 py-2", checked && "border-emerald-200 bg-emerald-50/70")}>
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <p className="truncate text-sm font-medium">{title}</p>
          {badges.map((badge) => (
            <Badge key={badge} variant="outline">{badge}</Badge>
          ))}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} aria-label={`Use ${title}`} />
    </div>
  );
}

function ParallelTestPanel({
  state,
}: {
  state: ParallelTestState;
}) {
  const progress = state.total > 0 ? Math.round((state.completed / state.total) * 100) : 0;
  const resolverTarget = state.resolverTarget || 1;
  const terminal = state.status !== "running" && state.status !== "idle";
  const resolverText = state.resolvers.length
    ? `${state.resolvers.length}/${resolverTarget} target · 1+ can test`
    : `${resolverTarget} resolver target`;
  const candidateText = state.phase === "candidates"
    ? `${state.completed}/${state.total} configs tested`
    : resolverText;

  return (
    <div className="rounded-lg border bg-background/70 p-4">
      <div className="min-w-0">
        <h3 className="text-sm font-medium">Parallel test</h3>
        <p className="mt-1 text-xs text-muted-foreground">{state.message || parallelPhaseLabel(state.phase)}</p>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Badge variant={parallelTestStatusBadgeVariant(state.status)}>{parallelTestStatusLabel(state.status)}</Badge>
        <Badge variant="outline">{parallelPhaseLabel(state.phase)}</Badge>
        <Badge variant="outline">{candidateText}</Badge>
        {state.running > 0 && <Badge variant="outline">{state.running} running</Badge>}
        {terminal && state.finishedAt > 0 && <Badge variant="outline">{formatParallelFinishedAt(state.finishedAt)}</Badge>}
      </div>
      <Progress value={progress} className="mt-3 h-2 bg-background/80" />
      {state.error && (
        <Alert className="mt-3 border-red-100 bg-red-50 text-red-950">
          <AlertCircle />
          <AlertTitle>Parallel test failed</AlertTitle>
          <AlertDescription>{state.error}</AlertDescription>
        </Alert>
      )}
      {state.candidates.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          {state.candidates.map((candidate) => (
            <div key={candidate.id} className="min-w-0 rounded-md border bg-muted/30 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <p className="truncate text-xs font-medium">{candidate.name}</p>
                <span className="text-[11px] text-muted-foreground">{candidate.status}</span>
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                {candidate.status === "connected"
                  ? `${candidate.stability.toFixed(0)}% stability · ${parallelCandidateSpeedLabel(candidate)} · ${formatDuration(candidate.startDurationMs)} start`
                  : candidate.error || "Waiting"}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function StartupProgressMini({ progress }: { progress: RuntimeStatus["progress"] }) {
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      <div className="flex min-w-0 items-center gap-2">
        <Gauge className="size-3.5 shrink-0 text-muted-foreground" />
        <span className="text-xs font-medium">Startup</span>
        <span className="truncate text-xs text-muted-foreground">{progressSummary(progress)}</span>
      </div>
      <div className="flex min-w-[10rem] flex-1 items-center gap-2">
        <Progress value={progress.percent || 0} className="h-1 bg-background/80" />
        <span className="w-8 text-right text-xs font-medium tabular-nums">{progress.percent || 0}%</span>
      </div>
    </div>
  );
}

function ResolverHealthProgress({ progress }: { progress: RuntimeStatus["progress"] }) {
  if (!progress.total && !progress.completed && !progress.valid && !progress.rejected) {
    return (
      <p className="text-xs text-muted-foreground">Waiting for resolver health updates from MasterDNS.</p>
    );
  }

  return (
    <div className="rounded-md border bg-muted/25 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-medium">MTU checks</p>
        <span className="text-xs text-muted-foreground">{progress.percent || 0}%</span>
      </div>
      <Progress value={progress.percent || 0} className="mt-2 h-1 bg-background/80" />
      <ScannerStatStrip
        compact
        stats={[
          { label: "Completed", value: progress.completed || 0 },
          { label: "Total", value: progress.total || 0 },
          { label: "Valid", value: progress.valid || 0 },
          { label: "Rejected", value: progress.rejected || 0 },
        ]}
      />
    </div>
  );
}

function ConnectionUpgradeScannerPanel({
  scanner,
  progress,
  onSaveRestart,
  onRuntimeRestart,
  onKeepCurrent,
}: {
  scanner: ScannerState;
  progress: number;
  onSaveRestart: () => void;
  onRuntimeRestart: () => void;
  onKeepCurrent: () => void;
}) {
  const running = scanner.status === "running";
  const restartReady = Boolean(scanner.restartAvailable);
  const autoRestart = Boolean(scanner.autoRestart);
  const statusText = running ? "Scanning" : restartReady && autoRestart ? "Auto restart" : restartReady ? "Restart ready" : scanner.status;

  return (
    <div className="rounded-md border bg-muted/25 p-3">
      <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-sm font-medium">
            <Search className="size-3.5 text-emerald-700" />
            Resolver scan
          </h3>
          <p className="mt-1 text-xs text-muted-foreground">
            {scanner.message || "VPN is connected while the resolver scan runs in the background."}
          </p>
        </div>
        <div className="flex flex-wrap gap-2 md:justify-end">
          <Badge variant={restartReady ? "default" : "outline"}>{statusText}</Badge>
          <Badge variant="outline">{scanner.bootstrapResolverCount || 1} minimum</Badge>
          <Badge variant="outline">{scanner.valid} best</Badge>
        </div>
      </div>
      <Progress value={progress} className="mt-2 h-1 bg-background/80" />
      <ScannerStatStrip
        stats={[
          { label: "Completed", value: scanner.completed },
          { label: "Total", value: scanner.total },
          { label: "Valid", value: scanner.valid },
          { label: "Rejected", value: scanner.rejected },
        ]}
        compact
      />
      {restartReady && !autoRestart && (
        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" size="sm" onClick={onSaveRestart}>
            <Save />
            Save profile and restart
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={onRuntimeRestart}>
            <RotateCcw />
            Restart once
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={onKeepCurrent}>
            <Square />
            Keep current
          </Button>
        </div>
      )}
      {scanner.error && (
        <Alert className="mt-3 border-red-100 bg-red-50 text-red-950">
          <AlertCircle />
          <AlertTitle>Background scan failed</AlertTitle>
          <AlertDescription>{scanner.error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}

function ConnectionsPage({
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
  const isProfileLocked = profileSelectionLocked(state.runtime);
  const activeConnection = effectiveConnectionProfile(state) || state.connectionProfiles[0];
  const selected = activeConnection || state.connectionProfiles[0];
  const [draft, setDraft] = useState(selected);
  const [editorOpen, setEditorOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importType, setImportType] = useState<ImportType>("masterdns");
  const [exportText, setExportText] = useState("");
  const [exportTitle, setExportTitle] = useState("Export Connections");
  const [testRunning, setTestRunning] = useState(false);
  const [deleteDisabledRunning, setDeleteDisabledRunning] = useState(false);
  const [testResults, setTestResults] = useState<Record<string, ConnectionTestResult>>({});
  const [testScanningIds, setTestScanningIds] = useState<Record<string, boolean>>({});
  const [testCheckedAt, setTestCheckedAt] = useState<Record<string, number>>({});
  const [profileFilter, setProfileFilter] = useState<ConnectionProfileFilter>("all");
  const testRunRef = useRef(0);
  const runtimeBusy = state.runtime.status !== "disconnected" && state.runtime.status !== "failed";
  const missingDomain = !draft.domain.trim();
  const missingKey = !draft.encryptionKey.trim();
  const importDisabled = !importText.trim();
  const hasExportableConnections = state.connectionProfiles.some(isExportableConnection);
  const testedCount = Object.keys(testResults).length;
  const reachableCount = Object.values(testResults).filter((result) => result.ok).length;
  const disabledProfiles = useMemo(
    () => state.connectionProfiles.filter((profile) => testResults[profile.id] && !testResults[profile.id].ok),
    [state.connectionProfiles, testResults]
  );
  const deletableDisabledProfiles = useMemo(
    () => disabledProfiles.filter((profile) => profile.id !== "default"),
    [disabledProfiles]
  );
  const filteredConnectionProfiles = useMemo(
    () => filterConnectionProfiles(state.connectionProfiles, testResults, testScanningIds, profileFilter),
    [profileFilter, state.connectionProfiles, testResults, testScanningIds]
  );

  useEffect(() => {
    if (!editorOpen) {
      setDraft(selected);
    }
  }, [editorOpen, selected]);

  async function saveConnectionDraft() {
    onError("");
    const profile = draft.id ? draft : { ...draft, id: makeConnectionProfileId(state.connectionProfiles) };
    try {
      const nextState = await backend.saveConnectionProfile(profile);
      onState(nextState);
      const savedProfile = nextState.connectionProfiles.find((candidate) => candidate.id === profile.id) || profile;
      setDraft(savedProfile);
      setEditorOpen(false);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function deleteConnectionDraft() {
    const deletedConnectionId = draft.id;
    if (!deletedConnectionId) {
      return;
    }
    onError("");
    try {
      const nextState = await backend.deleteConnectionProfile(deletedConnectionId);
      onState(nextState);
      setEditorOpen(false);
      setDraft(effectiveConnectionProfile(nextState) || nextState.connectionProfiles[0]);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  function openConnectionProfile(profile: ConnectionProfile) {
    onError("");
    setDraft(profile);
    setEditorOpen(true);
    if (isProfileLocked) {
      return;
    }
    backend.selectConnectionProfile(profile.id).then(onState).catch((err) => onError(messageFromError(err)));
  }

  function openNewConnectionProfile() {
    onError("");
    setDraft({
      id: "",
      name: "Connection",
      importType: "masterdns",
      domain: "",
      encryptionKey: "",
      encryptionMethod: 1,
      resolverProfileId: state.selectedResolverProfileId,
    });
    setEditorOpen(true);
  }

  async function exportSelectedProfile() {
    onError("");
    try {
      const link = await backend.exportConnectionProfileLink(draft);
      setExportTitle(draft.name.trim() || "Export Connection");
      setExportText(link);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function exportAllProfiles() {
    onError("");
    try {
      const links = await backend.exportAllConnectionProfileLinks();
      setExportTitle("Export All Connections");
      setExportText(links);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function importProfiles() {
    onError("");
    try {
      const result = await backend.importConnectionProfiles(importText, importType);
      onState(result.state);
      setImportText("");
      setImportType("masterdns");
      setImportOpen(false);
      onSuccess(`Imported ${result.imported} connection profile${result.imported === 1 ? "" : "s"}.`);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function testConnectionProfiles() {
    onError("");
    const profilesToTest = orderConnectionProfilesForTest(state.connectionProfiles, selected?.id);
    const runId = testRunRef.current + 1;
    testRunRef.current = runId;
    setTestRunning(true);
    setTestScanningIds(Object.fromEntries(profilesToTest.map((profile) => [profile.id, true])));
    setTestResults((current) => {
      const next = { ...current };
      profilesToTest.forEach((profile) => {
        delete next[profile.id];
      });
      return next;
    });

    let trustedResolvers: ConnectionTestResolver[] = [];
    try {
      for (const profile of profilesToTest) {
        try {
          const result = await backend.testConnectionProfile(profile, trustedResolvers);
          if (testRunRef.current !== runId) {
            return;
          }
          setTestResults((current) => ({ ...current, [result.profileId || profile.id]: result }));
          setTestCheckedAt((current) => ({ ...current, [profile.id]: Date.now() }));
          if (result.ok && trustedResolvers.length === 0) {
            trustedResolvers = usableConnectionTestResolvers(result.resolvers);
          }
        } catch (err) {
          if (testRunRef.current === runId) {
            onError(messageFromError(err));
          }
        } finally {
          if (testRunRef.current === runId) {
            setTestScanningIds((current) => {
              const next = { ...current };
              delete next[profile.id];
              return next;
            });
          }
        }
      }
    } finally {
      if (testRunRef.current === runId) {
        setTestRunning(false);
        setTestScanningIds({});
      }
    }
  }

  async function testConnectionProfile(profile: ConnectionProfile) {
    onError("");
    const runId = testRunRef.current + 1;
    testRunRef.current = runId;
    setTestRunning(true);
    setTestScanningIds({ [profile.id]: true });
    setTestResults((current) => {
      const next = { ...current };
      delete next[profile.id];
      return next;
    });
    try {
      const trustedResolvers = usableConnectionTestResolversFromResults(testResults);
      const result = await backend.testConnectionProfile(profile, trustedResolvers);
      if (testRunRef.current !== runId) {
        return;
      }
      setTestResults((current) => ({ ...current, [result.profileId || profile.id]: result }));
      setTestCheckedAt((current) => ({ ...current, [profile.id]: Date.now() }));
    } catch (err) {
      if (testRunRef.current === runId) {
        onError(messageFromError(err));
      }
    } finally {
      if (testRunRef.current === runId) {
        setTestRunning(false);
        setTestScanningIds({});
      }
    }
  }

  async function deleteDisabledConnections() {
    if (!deletableDisabledProfiles.length) {
      return;
    }
    onError("");
    setDeleteDisabledRunning(true);
    try {
      const nextState = await backend.deleteConnectionProfiles(deletableDisabledProfiles.map((profile) => profile.id));
      onState(nextState);
      onSuccess(`Deleted ${deletableDisabledProfiles.length} disabled connection profile${deletableDisabledProfiles.length === 1 ? "" : "s"}.`);
      const remainingIds = new Set(nextState.connectionProfiles.map((profile) => profile.id));
      setTestResults((current) => Object.fromEntries(Object.entries(current).filter(([id]) => remainingIds.has(id))));
      setTestScanningIds((current) => Object.fromEntries(Object.entries(current).filter(([id]) => remainingIds.has(id))));
      setTestCheckedAt((current) => Object.fromEntries(Object.entries(current).filter(([id]) => remainingIds.has(id))));
      if (!remainingIds.has(draft.id)) {
        setDraft(effectiveConnectionProfile(nextState) || nextState.connectionProfiles[0]);
      }
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setDeleteDisabledRunning(false);
    }
  }

  return (
    <>
      <PageShell
        eyebrow="Connections"
        title="Connection Profiles"
        actions={
          <>
            <Button variant="outline" disabled={missingDomain || missingKey} onClick={exportSelectedProfile}>
              <FileText />
              Export selected
            </Button>
            <Button variant="outline" disabled={!hasExportableConnections} onClick={exportAllProfiles}>
              <ListChecks />
              Export all
            </Button>
            <Button variant="outline" onClick={() => setImportOpen(true)}>
              <Upload />
              Import
            </Button>
            <Button variant="outline" onClick={openNewConnectionProfile}>
              <Plus />
              New
            </Button>
          </>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/30 px-3 py-2.5">
            <div className="flex items-center gap-4 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-muted-foreground">Total:</span>
                <span className="font-semibold">{state.connectionProfiles.length}</span>
              </div>
              {testedCount > 0 && (
                <>
                  <div className="h-4 w-px bg-border" />
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">Reachable:</span>
                    <span className="font-semibold text-emerald-600 dark:text-emerald-500">{reachableCount}</span>
                  </div>
                </>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={!state.connectionProfiles.length || testRunning || runtimeBusy}
                    onClick={testConnectionProfiles}
                    aria-label="Test all MasterDNS connections"
                  >
                    <Wifi className={cn("size-3.5", testRunning && "animate-pulse")} />
                    <span className="hidden sm:inline">Test all</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Test all MasterDNS connections</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={!deletableDisabledProfiles.length || deleteDisabledRunning || testRunning || runtimeBusy}
                    onClick={deleteDisabledConnections}
                    aria-label="Delete disabled MasterDNS connections"
                  >
                    <Trash2 className="size-3.5" />
                    <span className="hidden sm:inline">Delete disabled</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Delete profiles that failed the latest test</TooltipContent>
              </Tooltip>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 border-b bg-background/50 px-3 py-2">
            {connectionProfileFilterOptions.map(([filter, label]) => (
              <Button
                key={filter}
                type="button"
                variant={profileFilter === filter ? "secondary" : "ghost"}
                size="sm"
                className={cn(
                  "h-7 gap-1.5 rounded-full",
                  profileFilter === filter && "shadow-sm"
                )}
                onClick={() => setProfileFilter(filter)}
              >
                {filter === "reachable" && <CheckCircle2 className="size-3" />}
                {filter === "disabled" && <AlertCircle className="size-3" />}
                {label}
                <Badge variant="outline" className="ml-0.5 px-1.5 text-[10px]">
                  {connectionFilterCount(state.connectionProfiles, testResults, testScanningIds, filter)}
                </Badge>
              </Button>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] table-fixed text-left">
              <colgroup>
                <col className="w-[35%]" />
                <col className="w-[25%]" />
                <col className="w-[20%]" />
                <col className="w-[15%]" />
                <col className="w-[5%]" />
              </colgroup>
              <thead className="sticky top-0 z-10 border-b bg-muted/50 backdrop-blur-sm text-xs uppercase text-muted-foreground shadow-sm">
                <tr>
                  <th className="px-3 py-2 font-medium">Profile</th>
                  <th className="px-3 py-2 font-medium">Domain</th>
                  <th className="px-3 py-2 font-medium">Resolver</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 text-right font-medium">Test</th>
                </tr>
              </thead>
              <tbody>
                {filteredConnectionProfiles.map((profile) => {
                  const result = testResults[profile.id];
                  const scanning = Boolean(testScanningIds[profile.id]);
                  const selectedProfile = profile.id === selected?.id;
                  const resolverName =
                    state.resolverProfiles.find((resolver) => resolver.id === profile.resolverProfileId)?.name ||
                    state.resolverProfiles.find((resolver) => resolver.id === state.selectedResolverProfileId)?.name ||
                    "Default";
                  return (
                    <tr
                      key={profile.id}
                      role="button"
                      tabIndex={0}
                      className={cn(
                        "cursor-pointer border-b text-sm table-row-transition last:border-b-0 hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
                        selectedProfile && "bg-muted/40",
                        connectionTestRowClass(result, scanning)
                      )}
                      onClick={() => openConnectionProfile(profile)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          openConnectionProfile(profile);
                        }
                      }}
                    >
                      <td className="min-w-0 px-3 py-2.5">
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="truncate font-medium">{profile.name || "Connection"}</span>
                          <Badge variant="secondary" className="shrink-0 text-[10px] px-1.5">
                            {importTypeLabel(profile.importType)}
                          </Badge>
                          <Badge variant="outline" className="shrink-0 text-[10px] px-1.5">
                            {encryptionMethodLabel(profile.encryptionMethod)}
                          </Badge>
                          {selectedProfile && (
                            <Badge variant="outline" className="shrink-0 text-[10px] px-1.5">
                              Selected
                            </Badge>
                          )}
                        </div>
                        <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                          <span className="shrink-0">{formatConnectionTestCheckedAt(testCheckedAt[profile.id], scanning)}</span>
                          <span>·</span>
                          <span className="truncate">{resolverName}</span>
                        </div>
                      </td>
                      <td className="min-w-0 px-3 py-2.5">
                        <span className="block truncate">{profile.domain || "No domain"}</span>
                        {result?.resolver && (
                          <span className="mt-1 block truncate font-mono text-[11px] text-muted-foreground">{result.resolver}</span>
                        )}
                      </td>
                      <td className="min-w-0 px-3 py-2.5">
                        <span className="block truncate">{resolverName}</span>
                      </td>
                      <td className="px-3 py-2.5" title={result?.message || undefined}>
                        <Badge variant={result ? (result.ok ? "default" : "destructive") : "outline"} className={connectionTestBadgeClass(result, scanning)}>
                          {connectionTestBadgeLabel(result, scanning)}
                        </Badge>
                      </td>
                      <td className="px-3 py-3 text-right">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon-sm"
                              disabled={testRunning || runtimeBusy}
                              aria-label={`Test ${profile.name || "connection profile"}`}
                              onClick={(event) => {
                                event.stopPropagation();
                                void testConnectionProfile(profile);
                              }}
                              onKeyDown={(event) => event.stopPropagation()}
                            >
                              <Wifi className={cn(scanning && "animate-pulse")} />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>{runtimeBusy ? "Stop active connection first" : "Test connection"}</TooltipContent>
                        </Tooltip>
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
            <DialogTitle>{draft.id ? draft.name : "New connection"}</DialogTitle>
            <DialogDescription>MasterDNS/StormDNS route</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto pr-1">
            <FieldGroup className="grid gap-4 md:grid-cols-2">
              <TextField label="Name" value={draft.name} onChange={(name) => setDraft({ ...draft, name })} />
              <SelectField
                label="Import type"
                value={normalizeImportType(draft.importType)}
                onChange={(nextImportType) => setDraft({ ...draft, importType: nextImportType })}
                options={importTypeOptions}
              />
              <TextField
                label="MasterDNS/StormDNS domain"
                value={draft.domain}
                onChange={(domain) => setDraft({ ...draft, domain })}
                placeholder="v.example.com"
                error={missingDomain ? "MasterDNS/StormDNS domain is required." : undefined}
              />
              <SecretField
                label="Encryption key"
                value={draft.encryptionKey}
                onChange={(encryptionKey) => setDraft({ ...draft, encryptionKey })}
                error={missingKey ? "Encryption key is required." : undefined}
                revealable
              />
              <SelectField
                label="Encryption"
                value={draft.encryptionMethod}
                onChange={(encryptionMethod) => setDraft({ ...draft, encryptionMethod: Number(encryptionMethod) })}
                options={[
                  [0, "None"],
                  [1, "XOR"],
                  [2, "ChaCha20"],
                  [3, "AES-128-GCM"],
                  [4, "AES-192-GCM"],
                  [5, "AES-256-GCM"],
                ]}
              />
              <SelectField
                label="Resolver profile"
                value={draft.resolverProfileId || state.selectedResolverProfileId}
                onChange={(resolverProfileId) => setDraft({ ...draft, resolverProfileId: String(resolverProfileId) })}
                options={state.resolverProfiles.map((profile) => [profile.id, profile.name])}
              />
            </FieldGroup>
          </div>
          <DialogFooter className="sm:justify-between">
            {draft.id !== "default" && Boolean(draft.id) ? (
              <Button type="button" variant="destructive" onClick={deleteConnectionDraft} className="sm:mr-auto">
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
              <Button type="button" onClick={saveConnectionDraft}>
                <Save />
                Save
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] overflow-hidden sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Import Connections</DialogTitle>
            <DialogDescription>Paste one or more MasterDNS/StormDNS profile links.</DialogDescription>
          </DialogHeader>
          <TextAreaField
            label="Profiles"
            value={importText}
            onChange={setImportText}
            placeholder={"masterdns://...\nstormdns://..."}
            className="h-[min(45svh,18rem)] min-h-0 resize-none overflow-auto font-mono text-xs"
          />
          <SelectField
            label="Import type"
            value={importType}
            onChange={setImportType}
            options={importTypeOptions}
            description="Used when pasted links do not carry an explicit type marker."
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              Cancel
            </Button>
            <Button disabled={importDisabled} onClick={importProfiles}>
              <Download />
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(exportText)} onOpenChange={(open) => !open && setExportText("")}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{exportTitle}</DialogTitle>
            <DialogDescription>Copy these MasterDNS/StormDNS profile links for import on another device.</DialogDescription>
          </DialogHeader>
          <Textarea
            readOnly
            value={exportText}
            className="h-[min(45svh,18rem)] min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
          />
          <DialogFooter>
            <Button type="button" onClick={() => navigator.clipboard?.writeText(exportText)}>
              <Copy />
              Copy links
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </>
  );
}

function orderConnectionProfilesForTest(profiles: ConnectionProfile[], selectedId?: string): ConnectionProfile[] {
  if (!selectedId) {
    return [...profiles];
  }
  return [...profiles].sort((left, right) => {
    if (left.id === selectedId) {
      return -1;
    }
    if (right.id === selectedId) {
      return 1;
    }
    return 0;
  });
}

function usableConnectionTestResolvers(resolvers: ConnectionTestResolver[] | null | undefined): ConnectionTestResolver[] {
  return (resolvers || []).filter((resolver) =>
    Boolean(resolver.endpoint?.trim()) && resolver.uploadMtu > 0 && resolver.downloadMtu > 0
  );
}

function usableConnectionTestResolversFromResults(results: Record<string, ConnectionTestResult>): ConnectionTestResolver[] {
  for (const result of Object.values(results)) {
    if (!result.ok) {
      continue;
    }
    const resolvers = usableConnectionTestResolvers(result.resolvers);
    if (resolvers.length) {
      return resolvers;
    }
  }
  return [];
}

function connectionTestRowClass(result?: ConnectionTestResult, scanning = false): string {
  if (scanning) {
    return "bg-amber-50/70 hover:bg-amber-100/70 dark:bg-amber-950/20 dark:hover:bg-amber-950/30";
  }
  if (!result) {
    return "";
  }
  if (result.ok) {
    return "bg-emerald-50/80 hover:bg-emerald-100/80 dark:bg-emerald-950/25 dark:hover:bg-emerald-950/35";
  }
  return "bg-red-50/80 hover:bg-red-100/80 dark:bg-red-950/25 dark:hover:bg-red-950/35";
}

function connectionTestBadgeClass(result?: ConnectionTestResult, scanning = false): string {
  if (scanning) {
    return "border-amber-300 bg-amber-100 text-amber-900 dark:border-amber-900/60 dark:bg-amber-500/20 dark:text-amber-200";
  }
  if (!result) {
    return "text-muted-foreground";
  }
  if (result.ok) {
    return "bg-emerald-600 text-white hover:bg-emerald-600 dark:bg-emerald-500 dark:text-emerald-950 dark:hover:bg-emerald-500";
  }
  return "bg-red-600/10 text-red-700 hover:bg-red-600/10 dark:bg-red-500/20 dark:text-red-300 dark:hover:bg-red-500/20";
}

function connectionTestBadgeLabel(result?: ConnectionTestResult, scanning = false): string {
  if (scanning) {
    return "Testing";
  }
  if (!result) {
    return "Not checked";
  }
  if (result.ok) {
    return result.latencyMs > 0 ? `${result.latencyMs} ms` : "Connected";
  }
  if (result.message === "Domain is required") {
    return "No domain";
  }
  if (result.message === "Encryption key is required") {
    return "No key";
  }
  return "Disabled";
}

function filterConnectionProfiles(
  profiles: ConnectionProfile[],
  results: Record<string, ConnectionTestResult>,
  scanningIds: Record<string, boolean>,
  filter: ConnectionProfileFilter
): ConnectionProfile[] {
  if (filter === "all") {
    return profiles;
  }
  return profiles.filter((profile) => connectionProfileMatchesFilter(results[profile.id], Boolean(scanningIds[profile.id]), filter));
}

function connectionFilterCount(
  profiles: ConnectionProfile[],
  results: Record<string, ConnectionTestResult>,
  scanningIds: Record<string, boolean>,
  filter: ConnectionProfileFilter
): number {
  return filterConnectionProfiles(profiles, results, scanningIds, filter).length;
}

function connectionProfileMatchesFilter(result: ConnectionTestResult | undefined, scanning: boolean, filter: ConnectionProfileFilter): boolean {
  switch (filter) {
    case "reachable":
      return Boolean(result?.ok);
    case "disabled":
      return Boolean(result && !result.ok);
    case "unchecked":
      return !result && !scanning;
    default:
      return true;
  }
}

function formatConnectionTestCheckedAt(value?: number, scanning = false): string {
  if (scanning) {
    return "Checking";
  }
  if (!value) {
    return "Unchecked";
  }
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
  if (elapsedSeconds < 60) {
    return "Just now";
  }
  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  if (elapsedMinutes < 60) {
    return `${elapsedMinutes}m ago`;
  }
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function WhiteDNSVPNPage({
  state,
  onState,
  onError,
}: {
  state: AppState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const runtime = state.runtime;
  const selectedSettings = effectiveV2RaySettingsProfile(state);
  const active = whiteDNSVPNRuntimeActive(state);
  const runtimeBusy = runtime.status !== "disconnected" && runtime.status !== "failed";
  const canStart = runtime.status === "disconnected" || runtime.status === "failed";
  const [settingsSaving, setSettingsSaving] = useState(false);
  const localConnectPending = settingsSaving && !active && canStart;
  const setupStatus = localConnectPending ? "connecting" : active ? runtime.status : runtimeBusy ? "connecting" : "disconnected";
  const setupStatusLabel = localConnectPending || (active && runtime.status === "connecting") ? "Connecting VPN" : active ? statusLabel(runtime.status) : runtimeBusy ? "Busy" : "Disconnected";
  const localProxyEndpoint = runtimeProxyDisplayEndpoint(runtime) || (selectedSettings ? proxyEndpoint(selectedSettings.listenIp, selectedSettings.listenPort) : "-");
  const allowLanEnabled = Boolean(selectedSettings?.allowLan);
  const tunModeEnabled = Boolean(selectedSettings?.tunEnabled);
  const systemProxyEffective = Boolean(selectedSettings?.setSystemProxy);
  const settingsControlsDisabled = settingsSaving || (active && runtime.status === "connecting") || (runtimeBusy && !active);
  const selectedSettingsMissing = !selectedSettings || !selectedSettings.listenIp.trim() || selectedSettings.listenPort <= 0;
  const connectDisabled = !canStart || settingsSaving || selectedSettingsMissing || (runtimeBusy && !active);
  const settingsSelectorLabel = selectedSettings?.name || "Default Proxy";
  const settingsSelectorEndpoint = selectedSettings ? `${selectedSettings.listenIp}:${selectedSettings.listenPort}` : "No local proxy";
  const connectedFrontingIP = active ? runtime.frontingIp : "";
  const dashboardTitle = localConnectPending
    ? "Connecting WhiteDNS VPN"
    : active
      ? runtime.status === "connecting"
        ? "Connecting WhiteDNS VPN"
        : runtime.status === "connected"
          ? "WhiteDNS VPN connected"
          : runtime.message || "WhiteDNS VPN"
      : runtimeBusy
        ? "Another runtime is active"
        : "WhiteDNS VPN ready";
  const dashboardDescription = localConnectPending
    ? "Testing available connections before starting VPN."
    : active
      ? runtime.status === "connected"
        ? `Proxy listening on ${localProxyEndpoint}`
        : runtime.status === "connecting"
          ? runtime.progress.phase
            ? progressLabel(runtime.progress.phase, runtime.progress.percent)
            : "Starting secure connection."
          : runtime.message || "WhiteDNS VPN runtime"
      : runtimeBusy
        ? "Disconnect the active runtime before starting WhiteDNS VPN."
        : "Runtime idle";
  const frontingIps = Array.isArray(state.whiteDNSVPNFrontingIps) ? state.whiteDNSVPNFrontingIps : [];
  const [frontingInput, setFrontingInput] = useState("");
  const statusMetrics = [
    { label: "Local proxy", value: localProxyEndpoint, icon: Monitor },
    ...(connectedFrontingIP ? [{ label: "Fronting IP", value: connectedFrontingIP, icon: Shield }] : []),
    { label: "Download", value: formatSpeed(runtime.stats.downloadSpeedBytesPerSecond), icon: Download },
    { label: "Upload", value: formatSpeed(runtime.stats.uploadSpeedBytesPerSecond), icon: Upload },
  ];

  async function startWhiteDNSVPN() {
    if (connectDisabled) {
      return;
    }
    onError("");
    setSettingsSaving(true);
    try {
      onState(await backend.startWhiteDNSVPNConnection());
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSettingsSaving(false);
    }
  }

  async function stopRuntime() {
    onError("");
    setSettingsSaving(true);
    try {
      onState(await backend.stopConnection());
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSettingsSaving(false);
    }
  }

  async function refreshWhiteDNSVPN() {
    if (!active || runtime.status !== "connected" || settingsSaving) {
      return;
    }
    onError("");
    setSettingsSaving(true);
    try {
      onState(await backend.refreshWhiteDNSVPNConnection());
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSettingsSaving(false);
    }
  }

  async function applyWhiteDNSSettingsChange(change: () => Promise<AppState>) {
    if (settingsControlsDisabled) {
      return;
    }
    const shouldRestart = active && runtime.status === "connected";
    onError("");
    setSettingsSaving(true);
    try {
      if (shouldRestart) {
        onState(await backend.stopConnection());
      }
      onState(await change());
      if (shouldRestart) {
        onState(await backend.startWhiteDNSVPNConnection());
      }
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSettingsSaving(false);
    }
  }

  function editableWhiteDNSSettings(suffix: string): V2RaySettingsProfile | null {
    if (!selectedSettings) {
      return null;
    }
    if (selectedSettings.id !== "v2ray-settings-default") {
      return selectedSettings;
    }
    return {
      ...selectedSettings,
      id: makeV2RaySettingsProfileId(state.v2raySettingsProfiles),
      name: `${selectedSettings.name || "Default"} ${suffix}`,
    };
  }

  async function updateSelectedSettings(mutator: (profile: V2RaySettingsProfile) => V2RaySettingsProfile, suffix: string) {
    const editable = editableWhiteDNSSettings(suffix);
    if (!editable) {
      return;
    }
    await applyWhiteDNSSettingsChange(() => backend.saveV2RaySettingsProfile(normalizeV2RaySettingsProfile(mutator(editable))));
  }

  async function updateSystemProxy(setSystemProxy: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.setSystemProxy) === setSystemProxy) {
      return;
    }
    await updateSelectedSettings((profile) => ({ ...profile, setSystemProxy }), "Proxy");
  }

  async function updateTunMode(tunEnabled: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.tunEnabled) === tunEnabled) {
      return;
    }
    await updateSelectedSettings((profile) => ({ ...profile, tunEnabled }), "TUN");
  }

  async function updateAllowLAN(allowLan: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.allowLan) === allowLan) {
      return;
    }
    await updateSelectedSettings((profile) => withV2RaySettingsAllowLan(profile, allowLan), "LAN");
  }

  async function saveWhiteDNSFrontingIps(rawText = frontingInput, append = true) {
    if (settingsSaving) {
      return;
    }
    const pendingText = rawText.trim();
    if (append && !pendingText) {
      return;
    }
    const nextText = append ? [...frontingIps, pendingText].join(",") : rawText;
    const shouldRestart = active && runtime.status === "connected";
    onError("");
    setSettingsSaving(true);
    try {
      if (shouldRestart) {
        onState(await backend.stopConnection());
      }
      onState(await backend.saveWhiteDNSVPNFrontingIps(nextText));
      if (append) {
        setFrontingInput("");
      }
      if (shouldRestart) {
        onState(await backend.startWhiteDNSVPNConnection());
      }
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSettingsSaving(false);
    }
  }

  function removeWhiteDNSFrontingIp(ip: string) {
    void saveWhiteDNSFrontingIps(frontingIps.filter((item) => item !== ip).join(","), false);
  }

  return (
    <PageShell eyebrow="WhiteDNS VPN" title="WhiteDNS VPN">
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
                    <Badge variant="outline" className="h-6 gap-1 px-3">
                      <Monitor className="size-3" />
                      <span className="max-w-48 truncate font-mono">{localProxyEndpoint}</span>
                    </Badge>
                    <Badge variant="outline" className="h-6 gap-1 px-3">
                      <Shield className="size-3" />
                      <span className="font-mono">{connectedFrontingIP || "IP fronting auto"}</span>
                    </Badge>
                  </div>
                  <h2 className="text-2xl font-bold tracking-tight">{dashboardTitle}</h2>
                  <p className="mt-2 text-sm text-muted-foreground">{dashboardDescription}</p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:justify-end">
                {active && runtime.status === "connecting" ? (
                  <>
                    <Button type="button" variant="secondary" size="lg" className="h-11 min-w-36 px-6 font-semibold text-muted-foreground" disabled>
                      <RotateCcw className="size-5 animate-spin" />
                      Connecting...
                    </Button>
                    <Button type="button" variant="outline" size="lg" className="h-11 min-w-36 px-6 font-semibold" disabled={settingsSaving} onClick={stopRuntime}>
                      <Square className="size-5" />
                      Cancel
                    </Button>
                  </>
                ) : active && runtime.status !== "disconnected" && runtime.status !== "failed" ? (
                  <>
                    <Button
                      type="button"
                      variant="outline"
                      size="lg"
                      className="h-11 min-w-36 px-6 font-semibold"
                      disabled={settingsSaving || runtime.status !== "connected"}
                      onClick={refreshWhiteDNSVPN}
                    >
                      <RotateCcw className="size-5" />
                      Refresh
                    </Button>
                    <Button type="button" variant="outline" size="lg" className="h-11 min-w-36 px-6 font-semibold" disabled={settingsSaving} onClick={stopRuntime}>
                      <Square className="size-5" />
                      Disconnect
                    </Button>
                  </>
                ) : (
                  <Button
                    type="button"
                    size="lg"
                    className={cn("h-11 min-w-36 px-6 font-semibold", !connectDisabled && "bg-emerald-600 hover:bg-emerald-700")}
                    disabled={connectDisabled}
                    onClick={startWhiteDNSVPN}
                  >
                    {localConnectPending ? <RotateCcw className="size-5 animate-spin" /> : <Play className="size-5" />}
                    {localConnectPending ? "Connecting..." : "Connect VPN"}
                  </Button>
                )}
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
                      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Traffic</p>
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
              <Settings className="size-4" />
              Controls
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 p-3 pt-0">
            <div className="flex h-9 min-w-0 items-center justify-between gap-3 rounded-md border bg-background px-2.5 text-xs">
              <span className="truncate font-medium">{settingsSelectorLabel}</span>
              <span className="shrink-0 font-mono text-muted-foreground">{settingsSelectorEndpoint}</span>
            </div>

            <div className="space-y-2 rounded-md border bg-background p-2">
              <div className="flex min-w-0 gap-2">
                <Input
                  value={frontingInput}
                  disabled={settingsSaving}
                  placeholder="Add custom fronting IPs"
                  className="h-8 min-w-0 font-mono text-xs"
                  onChange={(event) => setFrontingInput(event.target.value)}
                  onPaste={(event) => {
                    const text = event.clipboardData.getData("text");
                    if (text.includes(",")) {
                      event.preventDefault();
                      void saveWhiteDNSFrontingIps(text);
                    }
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      void saveWhiteDNSFrontingIps();
                    }
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8 shrink-0"
                  disabled={settingsSaving || !frontingInput.trim()}
                  onClick={() => void saveWhiteDNSFrontingIps()}
                >
                  Add
                </Button>
              </div>
              {frontingIps.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {frontingIps.map((ip) => (
                    <Badge key={ip} variant="outline" className="h-6 gap-1 px-2 font-mono">
                      {ip}
                      <button
                        type="button"
                        className="rounded-sm text-muted-foreground hover:text-foreground"
                        disabled={settingsSaving}
                        onClick={() => removeWhiteDNSFrontingIp(ip)}
                        aria-label={`Remove ${ip}`}
                      >
                        <X className="size-3" />
                      </button>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div className="grid gap-2 sm:grid-cols-2">
              <label className="flex h-9 items-center justify-between gap-3 rounded-md border bg-background px-2.5 text-xs font-medium">
                <span>System proxy</span>
                <Switch
                  checked={systemProxyEffective}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateSystemProxy(checked)}
                  aria-label="Set WhiteDNS VPN system proxy"
                />
              </label>
              <label className="flex h-9 items-center justify-between gap-3 rounded-md border bg-background px-2.5 text-xs font-medium">
                <span>TUN</span>
                <Switch
                  checked={tunModeEnabled}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateTunMode(checked)}
                  aria-label="Enable WhiteDNS VPN TUN mode"
                />
              </label>
              <label className="flex h-9 items-center justify-between gap-3 rounded-md border bg-background px-2.5 text-xs font-medium">
                <span>Allow LAN</span>
                <Switch
                  checked={allowLanEnabled}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateAllowLAN(checked)}
                  aria-label="Allow LAN connection"
                />
              </label>
            </div>
          </CardContent>
        </Card>

      </div>

      {selectedSettingsMissing && (
        <Alert className="border-amber-200 bg-amber-50 text-amber-950">
          <AlertCircle />
          <AlertTitle>V2Ray settings required</AlertTitle>
          <AlertDescription>Choose a valid V2Ray local settings profile before connecting WhiteDNS VPN.</AlertDescription>
        </Alert>
      )}
      {runtimeBusy && !active && (
        <Alert>
          <AlertCircle />
          <AlertTitle>Another runtime is active</AlertTitle>
          <AlertDescription>Disconnect the active runtime before starting WhiteDNS VPN.</AlertDescription>
        </Alert>
      )}
    </PageShell>
  );
}

function V2RayDashboardPage({
  state,
  ping,
  onState,
  onError,
  onNavigate,
}: {
  state: AppState;
  ping: V2RayPingState;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onNavigate: (page: Page) => void;
}) {
  const runtime = state.runtime;
  const selectedProfile = effectiveV2RayProfile(state);
  const selectedSettings = effectiveV2RaySettingsProfile(state);
  const v2rayRuntimeActive = v2RayRuntimeActive(state);
  const canStart = runtime.status === "disconnected" || runtime.status === "failed";
  const isConnecting = runtime.status === "connecting" && v2rayRuntimeActive;
  const isConnected = runtime.status === "connected" && v2rayRuntimeActive;
  const runtimeBusy = runtime.status !== "disconnected" && runtime.status !== "failed";
  const missingProfile = !selectedProfile?.server.trim() || !v2rayProfileCredentialReady(selectedProfile);
  const missingSettings = !selectedSettings || !selectedSettings.listenIp.trim() || selectedSettings.listenPort <= 0;
  const connectDisabled = !canStart || missingProfile || missingSettings;
  const endpoint = runtimeProxyDisplayEndpoint(runtime) || (selectedSettings ? proxyEndpoint(selectedSettings.listenIp, selectedSettings.listenPort) : "-");
  const [lanIp, setLanIp] = useState("");
  const [lanIpStatus, setLanIpStatus] = useState<LanIpStatus>("idle");
  const [lanGuideCopyStatus, setLanGuideCopyStatus] = useState("");
  const [lanSaving, setLanSaving] = useState(false);
  const allowLanEnabled = Boolean(selectedSettings?.allowLan);
  const tunModeEnabled = Boolean(selectedSettings?.tunEnabled);
  const systemProxyEffective = Boolean(selectedSettings?.setSystemProxy);
  const guideListenPort = selectedSettings && selectedSettings.listenPort > 0 ? selectedSettings.listenPort : 10888;
  const detectedLanIp = lanIp || runtime.publicProxyIp;
  const lanGuideEndpoint = proxyEndpoint(detectedLanIp, guideListenPort);
  const localGuideEndpoint = proxyEndpoint("127.0.0.1", guideListenPort);
  const title = v2rayRuntimeActive ? runtime.message || "V2Ray" : runtimeBusy ? "Another runtime is active" : "V2Ray ready";
  const description = v2rayRuntimeActive
    ? runtime.status === "connected"
      ? `Proxy listening on ${endpoint}`
      : runtime.status === "connecting"
        ? progressLabel(runtime.progress.phase, runtime.progress.percent)
        : runtime.message || "V2Ray runtime"
    : runtimeBusy
      ? "Stop the active runtime before starting V2Ray."
      : selectedProfile?.server
        ? `${v2rayProtocolLabel(selectedProfile.protocol)} ${selectedProfile.server}:${selectedProfile.serverPort || 443}`
        : "No V2Ray server selected";
  const connectedTrafficMetrics = isConnected
    ? [
        ["Total data use", formatBytes(runtime.stats.totalDataUsageBytes)],
        ["Download speed", formatSpeed(runtime.stats.downloadSpeedBytesPerSecond)],
        ["Upload speed", formatSpeed(runtime.stats.uploadSpeedBytesPerSecond)],
      ]
    : [];
  const v2rayMetrics = [
    ["Protocol", selectedProfile ? v2rayProtocolLabel(selectedProfile.protocol) : "-"],
    ["Remote", selectedProfile?.server ? `${selectedProfile.server}:${selectedProfile.serverPort || 443}` : "-"],
    ["Local proxy", endpoint],
    ["TUN", tunModeEnabled ? "On" : "Off"],
    ["System proxy", systemProxyEffective ? "On" : "Off"],
    [enhancedConnectionLabel, selectedSettings?.iranRoutingEnabled ? "On" : "Off"],
    ...connectedTrafficMetrics,
  ];
  const selectedProfilePingLabel = selectedProfile
    ? v2rayPingSelectLabel(ping.results[selectedProfile.id], Boolean(ping.scanningIds[selectedProfile.id]))
    : "";
  const selectedProfileDetail =
    selectedProfile?.server
      ? selectedProfilePingLabel && selectedProfilePingLabel !== "No ping"
        ? `${selectedProfile.server} · ${selectedProfilePingLabel}`
        : selectedProfile.server
      : "No server";
  const dashboardProfileItems = useMemo(
    () => state.v2rayProfiles.map((profile) => ({ id: profile.id, title: profile.name || "V2Ray Connection" })),
    [state.v2rayProfiles]
  );

  useEffect(() => {
    if (!allowLanEnabled) {
      setLanIp("");
      setLanIpStatus("idle");
      setLanGuideCopyStatus("");
      return;
    }

    let cancelled = false;
    setLanIpStatus("loading");
    backend
      .getSystemLANIP()
      .then((ip) => {
        if (cancelled) {
          return;
        }
        const nextIp = (ip || "").trim();
        setLanIp(nextIp);
        setLanIpStatus(nextIp ? "ready" : "unavailable");
      })
      .catch(() => {
        if (!cancelled) {
          setLanIp("");
          setLanIpStatus("unavailable");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [allowLanEnabled, selectedSettings?.id]);

  useEffect(() => {
    setLanGuideCopyStatus("");
  }, [lanGuideEndpoint]);

  async function startV2Ray() {
    onError("");
    try {
      onState(await backend.startV2RayConnection());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function stopRuntime() {
    onError("");
    try {
      onState(await backend.stopConnection());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function updateAllowLAN(allowLan: boolean) {
    if (!selectedSettings || runtimeBusy) {
      return;
    }
    onError("");
    setLanSaving(true);
    try {
      let nextSettings = withV2RaySettingsAllowLan(selectedSettings, allowLan);
      if (selectedSettings.id === "v2ray-settings-default") {
        if (!allowLan) {
          return;
        }
        nextSettings = {
          ...nextSettings,
          id: makeV2RaySettingsProfileId(state.v2raySettingsProfiles),
          name: `${selectedSettings.name || "Default"} LAN`,
        };
      }
      onState(await backend.saveV2RaySettingsProfile(nextSettings));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setLanSaving(false);
    }
  }

  async function copyLanGuideEndpoint() {
    if (!lanGuideEndpoint) {
      return;
    }
    try {
      await navigator.clipboard?.writeText(lanGuideEndpoint);
      setLanGuideCopyStatus("Copied");
    } catch {
      setLanGuideCopyStatus("Copy failed");
    }
  }

  return (
    <PageShell
      eyebrow="V2Ray"
      title="Dashboard"
    >
      <Card className={cn("relative overflow-hidden transition-all duration-500 border-2", statusCardTone(v2rayRuntimeActive ? runtime.status : runtimeBusy ? "connecting" : "disconnected"))}>
        {/* Animated gradient overlay on connected state */}
        {isConnected && (
          <div className="absolute inset-0 bg-gradient-to-r from-emerald-500/5 via-emerald-500/10 to-emerald-500/5 animate-pulse-slow" />
        )}
        <CardContent className="relative z-10 flex flex-col gap-3 p-6">
          <div className="flex min-w-0 flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div className="flex min-w-0 items-start gap-4">
              {/* Large status indicator with glow */}
              <div className={cn(
                "flex items-center justify-center shrink-0 rounded-full w-14 h-14 transition-all duration-300",
                isConnected && "ring-4 ring-emerald-500/20 shadow-[0_0_20px_rgba(16,185,129,0.3)]"
              )}>
                <StatusDot status={v2rayRuntimeActive ? runtime.status : runtimeBusy ? "connecting" : "disconnected"} className="size-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  <Badge variant={statusBadgeVariant(v2rayRuntimeActive ? runtime.status : runtimeBusy ? "outline" : "secondary")} className="h-6 px-3 font-medium">
                    {v2rayRuntimeActive ? statusLabel(runtime.status) : runtimeBusy ? "Busy" : "Disconnected"}
                  </Badge>
                  <Badge variant="outline" className="h-6 px-3 gap-1">
                    <Server className="size-3" />
                    V2Ray
                  </Badge>
                </div>
                <h2 className="text-2xl font-bold tracking-tight animate-in">{title}</h2>
                <p className="mt-2 text-sm text-muted-foreground">{description}</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 md:shrink-0 md:justify-end">
              {isConnected || isConnecting ? (
                <Button
                  size="lg"
                  variant="outline"
                  className="h-11 min-w-36 px-6 font-semibold transition-all duration-300"
                  onClick={stopRuntime}
                >
                  <Square className="size-5" />
                  Disconnect
                </Button>
              ) : (
                <Button
                  size="lg"
                  disabled={connectDisabled}
                  className={cn(
                    "h-11 min-w-36 px-6 font-semibold transition-all duration-300",
                    !connectDisabled && [
                      "bg-emerald-600 hover:bg-emerald-700",
                      "shadow-[0_0_20px_rgba(16,185,129,0.25)]",
                      "hover:shadow-[0_0_30px_rgba(16,185,129,0.4)]",
                    ]
                  )}
                  onClick={startV2Ray}
                >
                  <Play className="size-5" />
                  Connect
                </Button>
              )}
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-lg border-2 bg-card p-4">
              <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Profile
              </label>
              <DashboardSelector
                label=""
                value={selectedProfile?.id || state.selectedV2RayProfileId}
                detail=""
                disabled={runtimeBusy}
                items={dashboardProfileItems}
                onChange={(id) => backend.selectV2RayProfile(id).then(onState).catch((err) => onError(messageFromError(err)))}
              />
              <p className="mt-2 text-xs text-muted-foreground truncate">
                {selectedProfileDetail}
              </p>
            </div>

            <div className="rounded-lg border-2 bg-card p-4">
              <label className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Settings
              </label>
              <DashboardSelector
                label=""
                value={selectedSettings?.id || state.selectedV2RaySettingsId}
                detail=""
                disabled={runtimeBusy}
                items={state.v2raySettingsProfiles.map((profile) => ({ id: profile.id, title: profile.name }))}
                onChange={(id) => backend.selectV2RaySettingsProfile(id).then(onState).catch((err) => onError(messageFromError(err)))}
              />
              <p className="mt-2 text-xs font-mono text-muted-foreground">
                {selectedSettings ? `${selectedSettings.listenIp}:${selectedSettings.listenPort}` : "No proxy"}
              </p>
            </div>
          </div>

          <div className="rounded-lg border-2 bg-card p-6">
            <div className={cn("grid gap-3", isConnected ? "md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6" : "md:grid-cols-2 lg:grid-cols-4")}>
              {v2rayMetrics.map(([label, value]) => {
                let Icon = Network;
                if (label === "Protocol") Icon = Radio;
                else if (label === "Remote") Icon = Server;
                else if (label === "Local proxy") Icon = Monitor;
                else if (label === "TUN") Icon = Network;
                else if (label === "System proxy") Icon = Settings;
                else if (label === enhancedConnectionLabel) Icon = Shield;
                else if (label === "Total data use") Icon = Download;
                else if (label === "Download speed") Icon = Download;
                else if (label === "Upload speed") Icon = Upload;

                return (
                  <div key={label} className="flex items-start gap-2 min-w-0">
                    <div className="rounded-md bg-primary/10 p-1.5 shrink-0">
                      <Icon className="size-3.5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
                      <p className="mt-0.5 truncate text-sm font-semibold">{value}</p>
                    </div>
                  </div>
                );
              })}
            </div>
            {isConnected && runtime.trafficMonitorMessage && (
              <div className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
                <AlertCircle className="size-3.5" />
                Traffic monitor: {runtime.trafficMonitorMessage}
              </div>
            )}
          </div>

          <V2RayLanConnectionBox
            enabled={allowLanEnabled}
            disabled={!selectedSettings || runtimeBusy || lanSaving}
            saving={lanSaving}
            runtimeBusy={runtimeBusy}
            systemIp={detectedLanIp}
            status={lanIpStatus}
            listenPort={guideListenPort}
            inboundType={selectedSettings?.inboundType || "mixed"}
            localEndpoint={localGuideEndpoint}
            lanEndpoint={lanGuideEndpoint}
            copyStatus={lanGuideCopyStatus}
            onCopyEndpoint={copyLanGuideEndpoint}
            onChange={updateAllowLAN}
          />
        </CardContent>
      </Card>

      {(missingProfile || missingSettings) && (
        <Alert className="border-amber-200 bg-amber-50 text-amber-950">
          <AlertCircle />
          <AlertTitle>V2Ray setup required</AlertTitle>
          <AlertDescription>
            {missingProfile ? "Add a V2Ray server and credential before connecting." : "Choose a valid V2Ray local settings profile."}
          </AlertDescription>
          <AlertAction>
            <Button variant="outline" size="sm" onClick={() => onNavigate(missingProfile ? "v2ray-profiles" : "v2ray-settings")}>
              Fix
            </Button>
          </AlertAction>
        </Alert>
      )}
    </PageShell>
  );
}

function V2RayProfilesPage({
  state,
  ping,
  onPingProfiles,
  onRealDelayProfiles,
  onCancelProfileTests,
  onForgetPingProfiles,
  onState,
  onError,
  onSuccess,
}: {
  state: AppState;
  ping: V2RayPingState;
  onPingProfiles: (profiles: V2RayProfile[]) => Promise<void>;
  onRealDelayProfiles: (profiles: V2RayProfile[]) => Promise<void>;
  onCancelProfileTests: () => Promise<void>;
  onForgetPingProfiles: (ids: string[]) => void;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
}) {
  const sidebar = useSidebar();
  const isProfileLocked = profileSelectionLocked(state.runtime);
  const fallbackDraft = useMemo(() => defaultV2RayDraft(), []);
  const activeProfile = effectiveV2RayProfile(state) || state.v2rayProfiles[0] || fallbackDraft;
  const selected = state.v2rayProfiles.find((profile) => profile.id === state.selectedV2RayProfileId) || activeProfile;
  const [draft, setDraft] = useState(selected);
  const [editorOpen, setEditorOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [exportText, setExportText] = useState("");
  const [dedupeRunning, setDedupeRunning] = useState(false);
  const [shareDialog, setShareDialog] = useState<V2RayShareDialogState | null>(null);
  const [selectedProfileIds, setSelectedProfileIds] = useState<Set<string>>(() => new Set());
  const [bulkMenuOpen, setBulkMenuOpen] = useState(false);
  const [bulkMenuPosition, setBulkMenuPosition] = useState({ top: 0, right: 0 });
  const bulkMenuRef = useRef<HTMLDivElement>(null);
  const bulkButtonRef = useRef<HTMLDivElement>(null);
  const [profileContextMenu, setProfileContextMenu] = useState<{ profile: V2RayProfile; top: number; left: number } | null>(null);
  const profileContextMenuRef = useRef<HTMLDivElement>(null);
  const profileTableScrollRef = useRef<HTMLDivElement>(null);
  const [profileListScrollTop, setProfileListScrollTop] = useState(0);
  const [profileListViewportHeight, setProfileListViewportHeight] = useState(640);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [profileSort, setProfileSort] = useState<V2RayProfileSort>({ column: "none", direction: "none" });
  const [profileStatusFilter, setProfileStatusFilter] = useState<V2RayStatusFilter>("all");
  const [profileTypeFilter, setProfileTypeFilter] = useState<V2RayTypeFilter>("all");
  const [profileSubscriptionFilter, setProfileSubscriptionFilter] = useState(v2raySubscriptionFilterAll);
  const [profileTableColumnWidths, setProfileTableColumnWidths] = useState<Record<V2RayProfileTableColumnId, number>>(loadV2RayProfileTableColumnWidths);
  const profileTableWidth = useMemo(() => v2rayProfileTableWidth(profileTableColumnWidths), [profileTableColumnWidths]);
  const runtime = state.runtime;
  const selectedSettings = effectiveV2RaySettingsProfile(state);
  const v2rayRuntimeActiveForSetup = v2RayRuntimeActive(state);
  const pingRunning = ping.running;
  const pingTestRunning = ping.running && ping.activeKind === "ping";
  const latencySpeedTestRunning = ping.running && (ping.activeKind === "speed" || ping.activeKind === "delay");
  const pingResults = ping.results;
  const pingScanningIds = ping.scanningIds;
  const pingCheckedAt = ping.checkedAt;
  const runtimeBusy = runtime.status !== "disconnected" && runtime.status !== "failed";
  const canStart = runtime.status === "disconnected" || runtime.status === "failed";
  const selectedSettingsMissing = !selectedSettings || !selectedSettings.listenIp.trim() || selectedSettings.listenPort <= 0;
  const setupStatus = v2rayRuntimeActiveForSetup ? runtime.status : runtimeBusy ? "connecting" : "disconnected";
  const setupStatusLabel = v2rayRuntimeActiveForSetup ? statusLabel(runtime.status) : runtimeBusy ? "Busy" : "Disconnected";
  const localProxyEndpoint = runtimeProxyDisplayEndpoint(runtime) || (selectedSettings ? proxyEndpoint(selectedSettings.listenIp, selectedSettings.listenPort) : "-");
  const controlBarInset = sidebar.isMobile
    ? { left: "1rem", right: "1rem" }
    : {
        left: sidebar.state === "collapsed" ? "calc(var(--sidebar-width-icon) + 1.5rem)" : "calc(var(--sidebar-width) + 1.5rem)",
        right: "1.5rem",
      };
  const allowLanEnabled = Boolean(selectedSettings?.allowLan);
  const tunModeEnabled = Boolean(selectedSettings?.tunEnabled);
  const systemProxyEffective = Boolean(selectedSettings?.setSystemProxy);
  const settingsControlsDisabled = settingsSaving || (v2rayRuntimeActiveForSetup && runtime.status === "connecting") || (runtimeBusy && !v2rayRuntimeActiveForSetup);
  const settingsItems = useMemo(
    () => state.v2raySettingsProfiles.map((profile) => ({ id: profile.id, title: profile.name })),
    [state.v2raySettingsProfiles]
  );
  const missingServer = !draft.server.trim();
  const missingCredential = !v2rayProfileCredentialReady(draft);
  const importDisabled = !importText.trim();
  const pingedCount = Object.keys(pingResults).length;
  const reachableCount = Object.values(pingResults).filter((result) => result.ok).length;
  const profileIndex = useMemo(
    () => buildV2RayProfileIndex(state.v2rayProfiles, pingResults, pingScanningIds),
    [pingResults, pingScanningIds, state.v2rayProfiles]
  );
  const hasExportableProfiles = profileIndex.hasExportable;
  const fastestProfile = profileIndex.fastestProfile;
  const failedProfiles = profileIndex.failedProfiles;
  const uncheckedProfiles = profileIndex.uncheckedProfiles;
  const profileFilters = useMemo<V2RayProfileFilters>(
    () => ({
      status: profileStatusFilter,
      type: profileTypeFilter,
      subscriptionId: profileSubscriptionFilter,
    }),
    [profileStatusFilter, profileSubscriptionFilter, profileTypeFilter]
  );
  const subscriptionFilterOptions = useMemo(
    () => v2raySubscriptionFilterOptions(profileIndex, state.v2raySubscriptions),
    [profileIndex, state.v2raySubscriptions]
  );
  const filterCounts = useMemo(
    () => buildV2RayFilterCounts(state.v2rayProfiles, pingResults, pingScanningIds, profileFilters),
    [pingResults, pingScanningIds, profileFilters, state.v2rayProfiles]
  );
  const filteredV2RayProfiles = useMemo(
    () => filterV2RayProfiles(state.v2rayProfiles, pingResults, pingScanningIds, profileFilters),
    [pingResults, pingScanningIds, profileFilters, state.v2rayProfiles]
  );
  const sortedV2RayProfiles = useMemo(
    () => sortV2RayProfilesByMetric(filteredV2RayProfiles, pingResults, pingScanningIds, profileSort),
    [filteredV2RayProfiles, pingResults, pingScanningIds, profileSort]
  );
  const virtualStartIndex = Math.min(
    sortedV2RayProfiles.length,
    Math.max(0, Math.floor(profileListScrollTop / v2rayProfileVirtualRowHeight) - v2rayProfileVirtualOverscan)
  );
  const virtualEndIndex = Math.min(
    sortedV2RayProfiles.length,
    Math.max(
      virtualStartIndex,
      Math.ceil((profileListScrollTop + profileListViewportHeight) / v2rayProfileVirtualRowHeight) + v2rayProfileVirtualOverscan
    )
  );
  const virtualV2RayProfiles = useMemo(
    () => sortedV2RayProfiles.slice(virtualStartIndex, virtualEndIndex),
    [sortedV2RayProfiles, virtualEndIndex, virtualStartIndex]
  );
  const virtualTopPadding = virtualStartIndex * v2rayProfileVirtualRowHeight;
  const virtualBottomPadding = Math.max(0, (sortedV2RayProfiles.length - virtualEndIndex) * v2rayProfileVirtualRowHeight);
  const visibleProfileIds = useMemo(() => sortedV2RayProfiles.map((profile) => profile.id), [sortedV2RayProfiles]);
  const selectedV2RayProfiles = useMemo(
    () => Array.from(selectedProfileIds, (id) => profileIndex.profileById[id]).filter((profile): profile is V2RayProfile => Boolean(profile)),
    [profileIndex.profileById, selectedProfileIds]
  );
  const selectedProfileCount = selectedV2RayProfiles.length;
  const selectedVisibleCount = countSelectedIds(visibleProfileIds, selectedProfileIds);
  const allVisibleSelected = visibleProfileIds.length > 0 && selectedVisibleCount === visibleProfileIds.length;
  const someVisibleSelected = selectedVisibleCount > 0 && !allVisibleSelected;
  const selectedFastestProfile = useMemo(
    () => fastestReachableV2RayProfile(selectedV2RayProfiles, pingResults),
    [pingResults, selectedV2RayProfiles]
  );
  const singleSelectedProfile = selectedProfileCount === 1 ? selectedV2RayProfiles[0] : undefined;
  const selectedConnectDisabled =
    !canStart || settingsSaving || selectedSettingsMissing || !singleSelectedProfile || !isConnectableV2RayProfile(singleSelectedProfile);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    window.localStorage.setItem(v2rayProfileTableColumnStorageKey, JSON.stringify(profileTableColumnWidths));
  }, [profileTableColumnWidths]);

  useEffect(() => {
    setSelectedProfileIds((current) => {
      const profileIds = new Set(state.v2rayProfiles.map((profile) => profile.id));
      const next = new Set([...current].filter((id) => profileIds.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [state.v2rayProfiles]);

  useEffect(() => {
    if (subscriptionFilterOptions.some(([filter]) => filter === profileSubscriptionFilter)) {
      return;
    }
    setProfileSubscriptionFilter(v2raySubscriptionFilterAll);
  }, [profileSubscriptionFilter, subscriptionFilterOptions]);

  useEffect(() => {
    if (!editorOpen) {
      setDraft(selected || fallbackDraft);
    }
  }, [editorOpen, fallbackDraft, selected]);

  useEffect(() => {
    if (!bulkMenuOpen) {
      return;
    }

    function onPointerDown(event: PointerEvent) {
      const target = event.target as Node;
      if (bulkMenuRef.current?.contains(target) || bulkButtonRef.current?.contains(target)) {
        return;
      }
      setBulkMenuOpen(false);
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setBulkMenuOpen(false);
      }
    }

    function onViewportChange() {
      positionBulkMenu();
    }

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onViewportChange);
    window.addEventListener("scroll", onViewportChange, true);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onViewportChange);
      window.removeEventListener("scroll", onViewportChange, true);
    };
  }, [bulkMenuOpen]);

  useEffect(() => {
    if (!profileContextMenu) {
      return;
    }

    function onPointerDown(event: PointerEvent) {
      const target = event.target as Node;
      if (profileContextMenuRef.current?.contains(target)) {
        return;
      }
      setProfileContextMenu(null);
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setProfileContextMenu(null);
      }
    }

    function onViewportChange() {
      setProfileContextMenu(null);
    }

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onViewportChange);
    window.addEventListener("scroll", onViewportChange, true);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onViewportChange);
      window.removeEventListener("scroll", onViewportChange, true);
    };
  }, [profileContextMenu]);

  useEffect(() => {
    const element = profileTableScrollRef.current;
    if (!element) {
      return;
    }
    const scrollElement = element;

    function updateViewportHeight() {
      setProfileListViewportHeight(scrollElement.clientHeight || 640);
    }

    updateViewportHeight();
    const resizeObserver = typeof ResizeObserver !== "undefined" ? new ResizeObserver(updateViewportHeight) : null;
    resizeObserver?.observe(scrollElement);
    window.addEventListener("resize", updateViewportHeight);
    return () => {
      resizeObserver?.disconnect();
      window.removeEventListener("resize", updateViewportHeight);
    };
  }, []);

  useEffect(() => {
    if (profileTableScrollRef.current) {
      profileTableScrollRef.current.scrollTop = 0;
    }
    setProfileListScrollTop(0);
  }, [profileSort, profileStatusFilter, profileSubscriptionFilter, profileTypeFilter]);

  function positionBulkMenu() {
    const rect = bulkButtonRef.current?.getBoundingClientRect();
    if (!rect) {
      return;
    }
    setBulkMenuPosition({
      top: Math.min(rect.bottom + 6, window.innerHeight - 16),
      right: Math.max(12, window.innerWidth - rect.right),
    });
  }

  function toggleBulkMenu() {
    if (!state.v2rayProfiles.length || dedupeRunning) {
      return;
    }
    setProfileContextMenu(null);
    positionBulkMenu();
    setBulkMenuOpen((open) => !open);
  }

  function runBulkAction(action: () => void | Promise<void>) {
    setBulkMenuOpen(false);
    void action();
  }

  function openProfileContextMenu(event: ReactMouseEvent<HTMLTableRowElement>, profile: V2RayProfile) {
    event.preventDefault();
    event.stopPropagation();
    setBulkMenuOpen(false);
    setProfileContextMenu({
      profile,
      top: Math.max(8, Math.min(event.clientY, window.innerHeight - 152)),
      left: Math.max(8, Math.min(event.clientX, window.innerWidth - 232)),
    });
  }

  function runProfileContextAction(action: () => void | Promise<void>) {
    setProfileContextMenu(null);
    void action();
  }

  function handleProfileTableScroll(event: ReactUIEvent<HTMLDivElement>) {
    setProfileListScrollTop(event.currentTarget.scrollTop);
  }

  function resizeProfileTableColumn(columnId: V2RayProfileTableColumnId, width: number) {
    const column = v2rayProfileTableColumns.find((candidate) => candidate.id === columnId);
    if (!column) {
      return;
    }
    setProfileTableColumnWidths((current) => ({
      ...current,
      [columnId]: clampNumber(Math.round(width), column.minWidth, column.maxWidth),
    }));
  }

  function resetProfileTableColumn(columnId: V2RayProfileTableColumnId) {
    const column = v2rayProfileTableColumns.find((candidate) => candidate.id === columnId);
    if (!column) {
      return;
    }
    setProfileTableColumnWidths((current) => ({ ...current, [columnId]: column.defaultWidth }));
  }

  function startProfileTableColumnResize(event: ReactPointerEvent<HTMLButtonElement>, columnId: V2RayProfileTableColumnId) {
    const column = v2rayProfileTableColumns.find((candidate) => candidate.id === columnId);
    if (!column) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const startWidth = profileTableColumnWidths[columnId];

    function onPointerMove(moveEvent: PointerEvent) {
      resizeProfileTableColumn(columnId, startWidth + moveEvent.clientX - startX);
    }

    function onPointerUp() {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
    }

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp, { once: true });
  }

  function v2rayHeaderCellClass(column: V2RayProfileTableColumn, extra?: string): string {
    return cn(
      "relative h-9 overflow-hidden px-1.5 py-2 font-medium",
      column.align === "center" && "text-center",
      column.align === "right" && "text-right",
      column.sticky === "right" && "v2ray-actions-header sticky right-0 z-20 border-l shadow-[-8px_0_12px_-12px_rgba(0,0,0,0.55)]",
      extra
    );
  }

  function renderProfileTableColumnResizeHandle(column: V2RayProfileTableColumn) {
    return (
      <button
        type="button"
        className="absolute inset-y-0 right-0 z-30 w-2 cursor-col-resize touch-none select-none rounded-sm outline-none hover:bg-primary/25 focus-visible:bg-primary/30"
        aria-label={`Resize ${column.label || "selection"} column`}
        onPointerDown={(event) => startProfileTableColumnResize(event, column.id)}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
        }}
        onDoubleClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          resetProfileTableColumn(column.id);
        }}
      />
    );
  }

  function v2rayStickyActionCellClass(selectedProfile = false): string {
    if (selectedProfile) {
      return "v2ray-actions-cell--selected";
    }
    return "";
  }

  function toggleProfileSelection(id: string, checked: boolean) {
    setSelectedProfileIds((current) => {
      const next = new Set(current);
      if (checked) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  }

  function toggleVisibleProfileSelection(checked: boolean) {
    setSelectedProfileIds((current) => {
      const next = new Set(current);
      visibleProfileIds.forEach((id) => {
        if (checked) {
          next.add(id);
        } else {
          next.delete(id);
        }
      });
      return next;
    });
  }

  async function saveDraft() {
    onError("");
    const profile = draft.id ? draft : { ...draft, id: makeV2RayProfileId(state.v2rayProfiles) };
    try {
      const nextState = await backend.saveV2RayProfile(profile);
      onState(nextState);
      const savedProfile = nextState.v2rayProfiles.find((candidate) => candidate.id === profile.id) || profile;
      setDraft(savedProfile);
      onForgetPingProfiles([savedProfile.id]);
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
      const nextState = await backend.deleteV2RayProfile(draft.id);
      onState(nextState);
      setEditorOpen(false);
      onForgetPingProfiles([draft.id]);
      const nextActive = effectiveV2RayProfile(nextState);
      setDraft(nextActive || nextState.v2rayProfiles[0] || fallbackDraft);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  function openExistingProfile(profile: V2RayProfile) {
    onError("");
    setDraft(profile);
    setEditorOpen(true);
  }

  function openNewProfile() {
    onError("");
    setDraft(defaultV2RayDraft());
    setEditorOpen(true);
  }

  async function importProfilesFromText(rawText: string) {
    if (!rawText.trim()) {
      return;
    }
    onError("");
    try {
      const result = await backend.importV2RayProfiles(rawText);
      onState(result.state);
      setImportText("");
      setImportOpen(false);
      onSuccess(`Imported ${result.imported} V2Ray profile${result.imported === 1 ? "" : "s"}.`);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function importProfiles() {
    await importProfilesFromText(importText);
  }

  async function importProfilesFromClipboard() {
    const clipboard = navigator.clipboard as Clipboard | undefined;
    if (!clipboard) {
      onError("Clipboard import is unavailable.");
      return;
    }
    try {
      const clipboardText = await clipboard.readText();
      if (!clipboardText.trim()) {
        onError("Clipboard does not contain a V2Ray profile.");
        return;
      }
      await importProfilesFromText(clipboardText);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function exportAllProfiles() {
    onError("");
    try {
      setExportText(await backend.exportAllV2RayProfileLinks());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function pingProfiles() {
    await onPingProfiles(state.v2rayProfiles);
  }

  async function pingSelectedProfiles() {
    await onPingProfiles(selectedV2RayProfiles);
  }

  async function realDelayProfiles() {
    await onRealDelayProfiles(state.v2rayProfiles);
  }

  async function realDelaySelectedProfiles() {
    await onRealDelayProfiles(selectedV2RayProfiles);
  }

  function toggleMetricSort(column: Exclude<V2RayProfileSortColumn, "none">) {
    setProfileSort((current) => {
      if (current.column !== column) {
        return { column, direction: column === "speed" ? "desc" : "asc" };
      }
      return { column, direction: current.direction === "asc" ? "desc" : "asc" };
    });
  }

  async function useFastestProfile() {
    if (!fastestProfile || settingsSaving) {
      return;
    }
    onError("");
    try {
      const nextState = await backend.selectV2RayProfile(fastestProfile.id);
      onState(nextState);
      onSuccess(`Selected fastest V2Ray profile: ${fastestProfile.name || fastestProfile.server}.`);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function useFastestSelectedProfile() {
    if (!selectedFastestProfile || settingsSaving) {
      return;
    }
    onError("");
    try {
      const nextState = await backend.selectV2RayProfile(selectedFastestProfile.id);
      onState(nextState);
      onSuccess(`Selected fastest selected V2Ray profile: ${selectedFastestProfile.name || selectedFastestProfile.server}.`);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function startSelectedProfile() {
    if (singleSelectedProfile) {
      await connectProfile(singleSelectedProfile);
    }
  }

  async function stopRuntime() {
    onError("");
    try {
      onState(await backend.stopConnection());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function applyV2RaySettingsChange(change: () => Promise<AppState>) {
    if (settingsControlsDisabled) {
      return;
    }
    const shouldRestart = v2rayRuntimeActiveForSetup && runtime.status === "connected";
    onError("");
    setSettingsSaving(true);
    try {
      if (shouldRestart) {
        onState(await backend.stopConnection());
      }
      onState(await change());
      if (shouldRestart) {
        onState(await backend.startV2RayConnection());
      }
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setSettingsSaving(false);
    }
  }

  function editableV2RaySettings(suffix: string): V2RaySettingsProfile | null {
    if (!selectedSettings) {
      return null;
    }
    if (selectedSettings.id !== "v2ray-settings-default") {
      return selectedSettings;
    }
    return {
      ...selectedSettings,
      id: makeV2RaySettingsProfileId(state.v2raySettingsProfiles),
      name: `${selectedSettings.name || "Default"} ${suffix}`,
    };
  }

  async function selectSettingsProfile(id: string) {
    if (!id || id === selectedSettings?.id) {
      return;
    }
    await applyV2RaySettingsChange(() => backend.selectV2RaySettingsProfile(id));
  }

  async function updateSelectedSettings(mutator: (profile: V2RaySettingsProfile) => V2RaySettingsProfile, suffix: string) {
    const editable = editableV2RaySettings(suffix);
    if (!editable) {
      return;
    }
    const nextSettings = normalizeV2RaySettingsProfile(mutator(editable));
    await applyV2RaySettingsChange(() => backend.saveV2RaySettingsProfile(nextSettings));
  }

  async function updateSystemProxy(setSystemProxy: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.setSystemProxy) === setSystemProxy) {
      return;
    }
    await updateSelectedSettings((profile) => ({ ...profile, setSystemProxy }), "Proxy");
  }

  async function updateTunMode(tunEnabled: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.tunEnabled) === tunEnabled) {
      return;
    }
    await updateSelectedSettings((profile) => ({ ...profile, tunEnabled }), "TUN");
  }

  async function updateEnhancedConnection(iranRoutingEnabled: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.iranRoutingEnabled) === iranRoutingEnabled) {
      return;
    }
    await updateSelectedSettings((profile) => ({ ...profile, iranRoutingEnabled }), "Enhanced");
  }

  async function updateAllowLAN(allowLan: boolean) {
    if (!selectedSettings || Boolean(selectedSettings.allowLan) === allowLan) {
      return;
    }
    await updateSelectedSettings((profile) => withV2RaySettingsAllowLan(profile, allowLan), "LAN");
  }

  async function connectProfile(profile: V2RayProfile) {
    if (runtimeBusy || settingsSaving || !isConnectableV2RayProfile(profile)) {
      return;
    }
    onError("");
    try {
      if (state.selectedV2RayProfileId !== profile.id) {
        onState(await backend.selectV2RayProfile(profile.id));
      }
      onState(await backend.startV2RayConnection());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function shareProfile(profile: V2RayProfile) {
    onError("");
    try {
      const link = await backend.exportV2RayProfileLink(profile);
      let qrDataUrl = "";
      let qrError = "";
      try {
        qrDataUrl = await QRCode.toDataURL(link, { margin: 1, width: 220 });
      } catch (err) {
        qrError = messageFromError(err);
      }
      setShareDialog({ profile, link, qrDataUrl, qrError, copyStatus: "" });
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function copySharedProfileLink() {
    if (!shareDialog) {
      return;
    }
    try {
      await navigator.clipboard?.writeText(shareDialog.link);
      setShareDialog({ ...shareDialog, copyStatus: "Copied" });
    } catch {
      setShareDialog({ ...shareDialog, copyStatus: "Copy failed" });
    }
  }

  async function deleteProfilesBulk(items: V2RayProfile[], label: string) {
    if (!items.length) {
      return;
    }
    onError("");
    setDedupeRunning(true);
    try {
      const nextState = await backend.deleteV2RayProfiles(items.map((profile) => profile.id));
      onState(nextState);
      onSuccess(`Deleted ${items.length} ${label} V2Ray profile${items.length === 1 ? "" : "s"}.`);
      onForgetPingProfiles(items.map((profile) => profile.id));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setDedupeRunning(false);
    }
  }

  async function deleteDuplicateProfiles() {
    onError("");
    setDedupeRunning(true);
    try {
      const result = await backend.deleteDuplicateV2RayProfiles();
      onState(result.state);
      onSuccess(
        result.removed > 0
          ? `Deleted ${result.removed} duplicate V2Ray profile${result.removed === 1 ? "" : "s"}.`
          : "No duplicate V2Ray profiles found."
      );
      const remainingIds = new Set(result.state.v2rayProfiles.map((profile) => profile.id));
      onForgetPingProfiles(state.v2rayProfiles.filter((profile) => !remainingIds.has(profile.id)).map((profile) => profile.id));
    } catch (err) {
      onError(messageFromError(err));
    } finally {
      setDedupeRunning(false);
    }
  }

  useEffect(() => {
    const shortcutsBlocked = editorOpen || importOpen || Boolean(shareDialog) || Boolean(exportText) || bulkMenuOpen || Boolean(profileContextMenu);
    if (shortcutsBlocked) {
      return;
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.defaultPrevented || isTextEntryKeyboardTarget(event.target)) {
        return;
      }
      const key = event.key.toLowerCase();
      const commandOrControl = event.metaKey || event.ctrlKey;

      if (commandOrControl && !event.altKey && key === "a") {
        event.preventDefault();
        setSelectedProfileIds(new Set(visibleProfileIds));
        return;
      }

      if (commandOrControl && !event.altKey && key === "v") {
        if (navigator.clipboard) {
          event.preventDefault();
          void importProfilesFromClipboard();
        }
        return;
      }

      if (
        (event.key === "Delete" || event.key === "Backspace") &&
        !event.repeat &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        selectedProfileCount > 0 &&
        !runtimeBusy &&
        !settingsSaving &&
        !dedupeRunning
      ) {
        event.preventDefault();
        void deleteProfilesBulk(selectedV2RayProfiles, "selected");
      }
    }

    function onPaste(event: ClipboardEvent) {
      if (event.defaultPrevented || isTextEntryKeyboardTarget(event.target)) {
        return;
      }
      const text = event.clipboardData?.getData("text") || "";
      if (!text.trim()) {
        return;
      }
      event.preventDefault();
      void importProfilesFromText(text);
    }

    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("paste", onPaste);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("paste", onPaste);
    };
  }, [
    bulkMenuOpen,
    dedupeRunning,
    editorOpen,
    exportText,
    importOpen,
    profileContextMenu,
    runtimeBusy,
    selectedProfileCount,
    selectedV2RayProfiles,
    settingsSaving,
    shareDialog,
    visibleProfileIds,
  ]);

  return (
    <>
      <PageShell
        eyebrow="V2Ray"
        title="V2Ray Setup"
        actions={
          <>
            <Button variant="outline" disabled={!hasExportableProfiles} onClick={exportAllProfiles}>
              <Upload />
              Export all
            </Button>
            <Button variant="outline" onClick={() => setImportOpen(true)}>
              <Download />
              Import
            </Button>
            <Button variant="outline" onClick={openNewProfile}>
              <Plus />
              New
            </Button>
          </>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
            <div className="min-w-0">
              <p className="text-sm font-semibold">Connection profiles</p>
              <p className="text-xs text-muted-foreground">
                {state.v2rayProfiles.length} profile{state.v2rayProfiles.length === 1 ? "" : "s"}
                {pingedCount > 0 ? `, ${reachableCount} reachable` : ""}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant={pingTestRunning ? "destructive" : "outline"}
                    disabled={!pingTestRunning && (!state.v2rayProfiles.length || pingRunning)}
                    onClick={pingTestRunning ? onCancelProfileTests : pingProfiles}
                    aria-label={pingTestRunning ? "Stop V2Ray ping test" : "Ping all V2Ray servers"}
                  >
                    {pingTestRunning ? <Square /> : <Wifi className={cn(pingRunning && ping.activeKind === "ping" && "animate-pulse")} />}
                    {pingTestRunning ? "Stop" : "Ping"}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{pingTestRunning ? "Stop ping test" : "Ping only"}</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant={latencySpeedTestRunning ? "destructive" : "outline"}
                    disabled={!latencySpeedTestRunning && (!state.v2rayProfiles.length || pingRunning)}
                    onClick={latencySpeedTestRunning ? onCancelProfileTests : realDelayProfiles}
                    aria-label={latencySpeedTestRunning ? "Stop V2Ray latency and speed test" : "Test latency and speed for V2Ray servers"}
                  >
                    {latencySpeedTestRunning ? <Square /> : <Gauge className={cn(pingRunning && ping.activeKind === "delay" && "animate-pulse")} />}
                    {latencySpeedTestRunning ? "Stop" : "Latency + speed"}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{latencySpeedTestRunning ? "Stop latency and speed test" : "Test speed first, then real delay"}</TooltipContent>
              </Tooltip>
              <Button
                type="button"
                variant="outline"
                disabled={!fastestProfile || isProfileLocked || settingsSaving}
                onClick={useFastestProfile}
              >
                <Gauge />
                Use fastest
              </Button>
              <div ref={bulkButtonRef} className="inline-flex">
                <Button
                  type="button"
                  variant="outline"
                  disabled={!state.v2rayProfiles.length || dedupeRunning}
                  aria-haspopup="menu"
                  aria-expanded={bulkMenuOpen}
                  onClick={toggleBulkMenu}
                >
                  <SlidersHorizontal />
                  Bulk actions
                  {selectedProfileCount > 0 && (
                    <Badge variant="secondary" className="ml-1 px-1.5">
                      {selectedProfileCount}
                    </Badge>
                  )}
                </Button>
              </div>
            </div>
          </div>
          {bulkMenuOpen && (
            <div
              ref={bulkMenuRef}
              role="menu"
              className="fixed z-[100] min-w-60 rounded-md border bg-popover p-1 text-popover-foreground shadow-xl"
              style={{ top: bulkMenuPosition.top, right: bulkMenuPosition.right }}
            >
              <div className="px-2 py-1.5 text-sm font-medium">
                {selectedProfileCount > 0
                  ? `${selectedProfileCount} selected profile${selectedProfileCount === 1 ? "" : "s"}`
                  : "No profiles selected"}
              </div>
              <BulkActionMenuItem disabled={!selectedProfileCount || pingRunning} onClick={() => runBulkAction(pingSelectedProfiles)}>
                <Wifi className={cn(pingRunning && ping.activeKind === "ping" && "animate-pulse")} />
                Ping selected
              </BulkActionMenuItem>
              <BulkActionMenuItem disabled={!selectedProfileCount || pingRunning} onClick={() => runBulkAction(realDelaySelectedProfiles)}>
                <Gauge className={cn(pingRunning && "animate-pulse")} />
                Latency + speed selected
              </BulkActionMenuItem>
              <BulkActionMenuItem disabled={!selectedFastestProfile || isProfileLocked || settingsSaving} onClick={() => runBulkAction(useFastestSelectedProfile)}>
                <Gauge />
                Use fastest selected
              </BulkActionMenuItem>
              <BulkActionMenuItem
                disabled={!singleSelectedProfile || runtimeBusy || settingsSaving || !isConnectableV2RayProfile(singleSelectedProfile)}
                onClick={() => runBulkAction(() => singleSelectedProfile && connectProfile(singleSelectedProfile))}
              >
                <Play />
                Connect selected
              </BulkActionMenuItem>
              <BulkActionMenuItem
                destructive
                disabled={!selectedProfileCount || runtimeBusy || settingsSaving}
                onClick={() => runBulkAction(() => deleteProfilesBulk(selectedV2RayProfiles, "selected"))}
              >
                <Trash2 />
                Delete selected
              </BulkActionMenuItem>
              <div className="-mx-1 my-1 h-px bg-border" />
              <div className="px-2 py-1.5 text-sm font-medium">All profiles</div>
              <BulkActionMenuItem disabled={!state.v2rayProfiles.length || pingRunning} onClick={() => runBulkAction(pingProfiles)}>
                <Wifi className={cn(pingRunning && ping.activeKind === "ping" && "animate-pulse")} />
                Ping all
              </BulkActionMenuItem>
              <BulkActionMenuItem disabled={!state.v2rayProfiles.length || pingRunning} onClick={() => runBulkAction(realDelayProfiles)}>
                <Gauge className={cn(pingRunning && "animate-pulse")} />
                Latency + speed all
              </BulkActionMenuItem>
              <BulkActionMenuItem disabled={!fastestProfile || isProfileLocked || settingsSaving} onClick={() => runBulkAction(useFastestProfile)}>
                <Gauge />
                Use fastest
              </BulkActionMenuItem>
              <BulkActionMenuItem disabled={state.v2rayProfiles.length < 2} onClick={() => runBulkAction(deleteDuplicateProfiles)}>
                <Trash2 />
                Delete duplicates
              </BulkActionMenuItem>
              <BulkActionMenuItem
                destructive
                disabled={!failedProfiles.length || runtimeBusy || settingsSaving}
                onClick={() => runBulkAction(() => deleteProfilesBulk(failedProfiles, "failed"))}
              >
                <Trash2 />
                Delete failed
              </BulkActionMenuItem>
              <BulkActionMenuItem
                destructive
                disabled={!uncheckedProfiles.length || runtimeBusy || settingsSaving}
                onClick={() => runBulkAction(() => deleteProfilesBulk(uncheckedProfiles, "unchecked"))}
              >
                <Trash2 />
                Delete unchecked
              </BulkActionMenuItem>
            </div>
          )}
          {profileContextMenu && (
            <div
              ref={profileContextMenuRef}
              role="menu"
              className="fixed z-[110] min-w-56 rounded-md border bg-popover p-1 text-popover-foreground shadow-xl"
              style={{ top: profileContextMenu.top, left: profileContextMenu.left }}
            >
              <div className="max-w-64 truncate px-2 py-1.5 text-sm font-medium">
                {profileContextMenu.profile.name || "V2Ray profile"}
              </div>
              <BulkActionMenuItem
                disabled={runtimeBusy || settingsSaving || !isConnectableV2RayProfile(profileContextMenu.profile)}
                onClick={() => runProfileContextAction(() => connectProfile(profileContextMenu.profile))}
              >
                <Play />
                Connect
              </BulkActionMenuItem>
              <BulkActionMenuItem onClick={() => runProfileContextAction(() => openExistingProfile(profileContextMenu.profile))}>
                <Pencil />
                Edit
              </BulkActionMenuItem>
              <BulkActionMenuItem
                disabled={pingRunning || Boolean(pingScanningIds[profileContextMenu.profile.id])}
                onClick={() => runProfileContextAction(() => onPingProfiles([profileContextMenu.profile]))}
              >
                <Wifi className={cn((pingRunning || pingScanningIds[profileContextMenu.profile.id]) && "animate-pulse")} />
                Ping
              </BulkActionMenuItem>
              <BulkActionMenuItem
                disabled={pingRunning || Boolean(pingScanningIds[profileContextMenu.profile.id])}
                onClick={() => runProfileContextAction(() => onRealDelayProfiles([profileContextMenu.profile]))}
              >
                <Gauge className={cn((pingRunning || pingScanningIds[profileContextMenu.profile.id]) && "animate-pulse")} />
                Latency + speed
              </BulkActionMenuItem>
              <BulkActionMenuItem
                disabled={!isExportableV2RayProfile(profileContextMenu.profile)}
                onClick={() => runProfileContextAction(() => shareProfile(profileContextMenu.profile))}
              >
                <Share2 />
                Share
              </BulkActionMenuItem>
              <BulkActionMenuItem
                destructive
                disabled={runtimeBusy || settingsSaving}
                onClick={() => runProfileContextAction(() => deleteProfilesBulk([profileContextMenu.profile], "selected"))}
              >
                <Trash2 />
                Delete
              </BulkActionMenuItem>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-3 border-b bg-background px-3 py-2">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-muted-foreground">Status</span>
              <Select value={profileStatusFilter} onValueChange={(value) => setProfileStatusFilter(value as V2RayStatusFilter)}>
                <SelectTrigger size="sm" className="min-w-[9.5rem] bg-card">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper" align="start">
                  {v2rayProfileStatusFilterOptions.map(([filter, label]) => (
                    <SelectItem key={filter} value={filter}>
                      <span className="flex min-w-0 items-center gap-3 pr-4">
                        <span className="truncate">{label}</span>
                        <span className="ml-auto text-xs tabular-nums text-muted-foreground">
                          {filterCounts.status[filter] || 0}
                        </span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-muted-foreground">Type</span>
              <Select value={profileTypeFilter} onValueChange={(value) => setProfileTypeFilter(value as V2RayTypeFilter)}>
                <SelectTrigger size="sm" className="min-w-[9rem] bg-card">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper" align="start">
                  {v2rayProfileTypeFilterOptions.map(([filter, label]) => (
                    <SelectItem key={filter} value={filter}>
                      <span className="flex min-w-0 items-center gap-3 pr-4">
                        <span className="truncate">{label}</span>
                        <span className="ml-auto text-xs tabular-nums text-muted-foreground">
                          {filterCounts.type[filter] || 0}
                        </span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="text-xs font-medium text-muted-foreground">Subs</span>
              <Select value={profileSubscriptionFilter} onValueChange={setProfileSubscriptionFilter}>
                <SelectTrigger size="sm" className="min-w-[12rem] max-w-full bg-card sm:min-w-[16rem]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent position="popper" align="start" className="max-w-[min(28rem,calc(100vw-2rem))]">
                  {subscriptionFilterOptions.map(([filter, label]) => (
                    <SelectItem key={filter} value={filter}>
                      <span className="flex min-w-0 items-center gap-3 pr-4">
                        <span className="truncate">{label}</span>
                        <span className="ml-auto text-xs tabular-nums text-muted-foreground">
                          {filterCounts.subscription[filter] || 0}
                        </span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div
            ref={profileTableScrollRef}
            className="max-h-[min(68svh,46rem)] overflow-auto"
            onScroll={handleProfileTableScroll}
          >
            <table className="table-fixed text-left" style={{ width: profileTableWidth, minWidth: profileTableWidth }}>
              <colgroup>
                {v2rayProfileTableColumns.map((column) => (
                  <col key={column.id} style={{ width: profileTableColumnWidths[column.id] }} />
                ))}
              </colgroup>
              <thead className="sticky top-0 z-10 border-b bg-muted/95 text-xs uppercase text-muted-foreground backdrop-blur supports-backdrop-filter:bg-muted/80">
                <tr>
                  {v2rayProfileTableColumns.map((column) => {
                    if (column.id === "select") {
                      return (
                        <th key={column.id} className={v2rayHeaderCellClass(column)}>
                          <input
                            ref={(node) => {
                              if (node) {
                                node.indeterminate = someVisibleSelected;
                              }
                            }}
                            type="checkbox"
                            className="size-4 rounded border-border accent-emerald-600"
                            checked={allVisibleSelected}
                            disabled={!visibleProfileIds.length}
                            aria-label="Select all visible V2Ray profiles"
                            aria-checked={someVisibleSelected ? "mixed" : allVisibleSelected}
                            onChange={(event) => toggleVisibleProfileSelection(event.target.checked)}
                            onClick={(event) => event.stopPropagation()}
                          />
                          {renderProfileTableColumnResizeHandle(column)}
                        </th>
                      );
                    }
                    if (column.id === "delay" || column.id === "speed") {
                      const metricDirection = profileSort.column === column.id ? profileSort.direction : "none";
                      return (
                        <th key={column.id} className={v2rayHeaderCellClass(column)}>
                          <div className={cn("flex min-w-0 items-center gap-1.5 truncate pr-2", column.align === "right" && "justify-end")}>
                            <button
                              type="button"
                              className="inline-flex shrink-0 items-center gap-1 rounded-md text-xs font-medium uppercase text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                              onClick={() => toggleMetricSort(column.id as "delay" | "speed")}
                              aria-label={`Sort V2Ray profiles by ${column.id === "delay" ? "ping" : "speed"}`}
                            >
                              <span className="truncate">{column.label}</span>
                              <ChevronDown
                                className={cn(
                                  "size-3 transition-transform",
                                  metricDirection === "asc" && "rotate-180",
                                  metricDirection === "none" && "opacity-40"
                                )}
                              />
                            </button>
                          </div>
                          {renderProfileTableColumnResizeHandle(column)}
                        </th>
                      );
                    }
                    return (
                      <th key={column.id} className={v2rayHeaderCellClass(column)}>
                        <span className="block truncate pr-2">{column.label}</span>
                        {renderProfileTableColumnResizeHandle(column)}
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody>
                {sortedV2RayProfiles.length === 0 && (
                  <tr>
                    <td colSpan={v2rayProfileTableColumns.length} className="px-3 py-8 text-center text-sm text-muted-foreground">
                      No V2Ray profiles match the current filters.
                    </td>
                  </tr>
                )}
                {virtualTopPadding > 0 && (
                  <tr aria-hidden="true">
                    <td colSpan={v2rayProfileTableColumns.length} className="border-0 p-0" style={{ height: virtualTopPadding }} />
                  </tr>
                )}
                {virtualV2RayProfiles.map((profile) => {
                  const result = pingResults[profile.id];
                  const scanning = Boolean(pingScanningIds[profile.id]);
                  const selectedProfile = profile.id === selected?.id;
                  const selectedForBulk = selectedProfileIds.has(profile.id);
                  const connectDisabled = runtimeBusy || settingsSaving || !isConnectableV2RayProfile(profile);
                  return (
                    <tr
                      key={profile.id}
                      style={{ height: v2rayProfileVirtualRowHeight }}
                      className={cn(
                        "border-b text-sm transition-colors last:border-b-0 hover:bg-muted/50",
                        selectedProfile && "bg-muted/40",
                        selectedForBulk && "shadow-[inset_3px_0_0_var(--primary)]"
                      )}
                      onContextMenu={(event) => openProfileContextMenu(event, profile)}
                    >
                      <td className="px-1 py-1 text-center">
                        <input
                          type="checkbox"
                          className="size-4 rounded border-border accent-emerald-600"
                          checked={selectedForBulk}
                          aria-label={`Select ${profile.name || "V2Ray profile"}`}
                          onChange={(event) => toggleProfileSelection(profile.id, event.target.checked)}
                          onClick={(event) => event.stopPropagation()}
                          onKeyDown={(event) => event.stopPropagation()}
                        />
                      </td>
                      <td className="px-1.5 py-1">
                        <span className="text-xs font-medium uppercase">{v2rayProtocolLabel(profile.protocol)}</span>
                      </td>
                      <td className="min-w-0 px-1.5 py-1" title={result?.message || undefined}>
                        <span className={cn("block truncate font-medium", selectedProfile && "text-primary")}>
                          {profile.name || "V2Ray Connection"}
                        </span>
                      </td>
                      <td className="min-w-0 px-1.5 py-1" title={profile.server || undefined}>
                        <span className="block truncate font-mono text-xs">{profile.server || "-"}</span>
                      </td>
                      <td className="px-1.5 py-1 font-mono text-xs">{profile.serverPort || 443}</td>
                      <td className="px-1.5 py-1 text-xs" title={v2rayNetworkLabel(profile.network)}>{v2rayNetworkLabel(profile.network)}</td>
                      <td className="px-1.5 py-1 text-xs">{profile.tls || profile.reality ? "tls" : "-"}</td>
                      <td className={cn("px-1.5 py-1 text-right text-xs tabular-nums", v2rayDelayClass(result, scanning))}>
                        {formatV2RayDelay(result, scanning)}
                      </td>
                      <td className={cn("px-1.5 py-1 text-right text-xs tabular-nums", v2raySpeedClass(result, scanning))}>
                        {formatV2RaySpeedResult(result, scanning)}
                      </td>
                      <td
                        className={cn(
                          "v2ray-actions-cell sticky right-0 z-[1] border-l px-1 py-1 text-right shadow-[-8px_0_12px_-12px_rgba(0,0,0,0.55)]",
                          v2rayStickyActionCellClass(selectedProfile || selectedForBulk)
                        )}
                      >
                        <div className="flex justify-end gap-0.5">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                disabled={connectDisabled}
                                aria-label={`Connect ${profile.name || "V2Ray profile"}`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void connectProfile(profile);
                                }}
                                onKeyDown={(event) => event.stopPropagation()}
                              >
                                <Play />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>{connectDisabled ? "Unavailable" : "Connect"}</TooltipContent>
                          </Tooltip>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                aria-label={`Share ${profile.name || "V2Ray profile"}`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void shareProfile(profile);
                                }}
                                onKeyDown={(event) => event.stopPropagation()}
                              >
                                <Share2 />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Share</TooltipContent>
                          </Tooltip>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                aria-label={`Edit ${profile.name || "V2Ray profile"}`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  openExistingProfile(profile);
                                }}
                                onKeyDown={(event) => event.stopPropagation()}
                              >
                                <Pencil />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Edit</TooltipContent>
                          </Tooltip>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon-sm"
                                disabled={runtimeBusy || settingsSaving}
                                aria-label={`Delete ${profile.name || "V2Ray profile"}`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void deleteProfilesBulk([profile], "selected");
                                }}
                                onKeyDown={(event) => event.stopPropagation()}
                              >
                                <Trash2 />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>{runtimeBusy || settingsSaving ? "Disconnect first" : "Delete"}</TooltipContent>
                          </Tooltip>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {virtualBottomPadding > 0 && (
                  <tr aria-hidden="true">
                    <td colSpan={v2rayProfileTableColumns.length} className="border-0 p-0" style={{ height: virtualBottomPadding }} />
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="h-24 shrink-0" aria-hidden="true" />
        <div className="fixed bottom-3 z-40" style={controlBarInset}>
          <div
            className={cn(
              "flex flex-col gap-2 rounded-lg border bg-background/95 px-3 py-2 shadow-lg backdrop-blur supports-backdrop-filter:bg-background/80 xl:flex-row xl:items-center xl:justify-between",
              setupStatus === "connected" && "border-emerald-200",
              setupStatus === "connecting" && "border-amber-200",
              setupStatus === "failed" && "border-red-200"
            )}
          >
            <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
              <span className="inline-flex items-center gap-2 text-sm font-semibold">
                <StatusDot status={setupStatus} className="size-2.5" />
                {setupStatusLabel}
              </span>
              <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">{localProxyEndpoint}</span>
            </div>
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Select
                value={selectedSettings?.id || state.selectedV2RaySettingsId}
                disabled={settingsControlsDisabled || !settingsItems.length}
                onValueChange={(id) => void selectSettingsProfile(id)}
              >
                <SelectTrigger size="sm" className="min-w-40 max-w-56 bg-card">
                  <SelectValue placeholder="Settings" />
                </SelectTrigger>
                <SelectContent position="popper" align="end">
                  {settingsItems.map((item) => (
                    <SelectItem key={item.id} value={item.id}>
                      {item.title}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <label className="inline-flex h-8 items-center gap-2 rounded-md border bg-card px-2 text-xs font-medium">
                <span>System proxy</span>
                <Switch
                  checked={systemProxyEffective}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateSystemProxy(checked)}
                  aria-label="Set V2Ray system proxy"
                />
              </label>
              <label className="inline-flex h-8 items-center gap-2 rounded-md border bg-card px-2 text-xs font-medium">
                <span>TUN</span>
                <Switch
                  checked={tunModeEnabled}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateTunMode(checked)}
                  aria-label="Enable V2Ray TUN mode"
                />
              </label>
              <label className="inline-flex h-8 items-center gap-2 rounded-md border bg-card px-2 text-xs font-medium">
                <span>Enhanced</span>
                <Switch
                  checked={Boolean(selectedSettings?.iranRoutingEnabled)}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateEnhancedConnection(checked)}
                  aria-label={`Enable ${enhancedConnectionLabel}`}
                />
              </label>
              <label className="inline-flex h-8 items-center gap-2 rounded-md border bg-card px-2 text-xs font-medium">
                <span>Allow LAN</span>
                <Switch
                  checked={allowLanEnabled}
                  disabled={!selectedSettings || settingsControlsDisabled}
                  onCheckedChange={(checked) => void updateAllowLAN(checked)}
                  aria-label="Allow LAN connection"
                />
              </label>

              {v2rayRuntimeActiveForSetup && runtime.status !== "disconnected" && runtime.status !== "failed" ? (
                <Button type="button" variant="outline" size="sm" disabled={settingsSaving} onClick={stopRuntime}>
                  <Square />
                  Disconnect
                </Button>
              ) : (
                <Button
                  type="button"
                  size="sm"
                  className={cn(!selectedConnectDisabled && "bg-emerald-600 hover:bg-emerald-700")}
                  disabled={selectedConnectDisabled}
                  onClick={startSelectedProfile}
                >
                  <Play />
                  Connect selected
                </Button>
              )}
            </div>
          </div>
        </div>
      </PageShell>

      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-5xl">
          <DialogHeader>
            <DialogTitle>{draft.id ? draft.name : "New V2Ray profile"}</DialogTitle>
            <DialogDescription>Xray direct profile</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto pr-1">
            <div className="space-y-6">
              <FieldSet>
                <FieldTitle className="text-base">Remote server</FieldTitle>
                <Separator />
                <FieldGroup className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  <TextField label="Name" value={draft.name} onChange={(name) => setDraft({ ...draft, name })} />
                  <SelectField
                    label="Protocol"
                    value={draft.protocol}
                    onChange={(protocol) => setDraft({ ...draft, protocol: normalizeV2RayProtocol(String(protocol)) })}
                    options={v2rayProtocolOptions}
                  />
                  <TextField
                    label="Server"
                    value={draft.server}
                    onChange={(server) => setDraft({ ...draft, server })}
                    placeholder="example.com"
                    error={missingServer ? "Server is required." : undefined}
                  />
                  <NumberField label="Server port" value={draft.serverPort} min={1} max={65535} onChange={(serverPort) => setDraft({ ...draft, serverPort })} />
                  {draft.protocol === "trojan" ? (
                    <SecretField
                      label="Password"
                      value={draft.password}
                      onChange={(password) => setDraft({ ...draft, password })}
                      error={missingCredential ? "Trojan password is required." : undefined}
                      revealable
                    />
                  ) : (draft.protocol === "vless" || draft.protocol === "vmess") ? (
                    <SecretField
                      label={draft.protocol === "vmess" ? "VMess UUID" : "VLESS UUID"}
                      value={draft.uuid}
                      onChange={(uuid) => setDraft({ ...draft, uuid })}
                      error={missingCredential ? "UUID is required." : undefined}
                      revealable
                    />
                  ) : draft.protocol === "shadowsocks" ? (
                    <>
                      <TextField label="Method" value={draft.shadowsocksMethod} onChange={(shadowsocksMethod) => setDraft({ ...draft, shadowsocksMethod })} placeholder="2022-blake3-aes-256-gcm" />
                      <SecretField label="Password" value={draft.password} onChange={(password) => setDraft({ ...draft, password })} error={missingCredential ? "Shadowsocks password is required." : undefined} revealable />
                      <ToggleField label="UDP over TCP" checked={draft.uot} onChange={(uot) => setDraft({ ...draft, uot })} />
                      {draft.uot && <NumberField label="UoT version" value={draft.uotVersion} min={1} max={2} onChange={(uotVersion) => setDraft({ ...draft, uotVersion })} />}
                    </>
                  ) : draft.protocol === "hysteria2" ? (
                    <>
                      <SecretField label="Auth" value={draft.hysteriaAuth} onChange={(hysteriaAuth) => setDraft({ ...draft, hysteriaAuth })} error={missingCredential ? "Hysteria2 auth is required." : undefined} revealable />
                      <NumberField label="UDP idle timeout" value={draft.hysteriaUdpIdleTimeout} min={0} onChange={(hysteriaUdpIdleTimeout) => setDraft({ ...draft, hysteriaUdpIdleTimeout })} />
                    </>
                  ) : draft.protocol === "wireguard" ? (
                    <>
                      <SecretField label="Private key" value={draft.wireGuardSecretKey} onChange={(wireGuardSecretKey) => setDraft({ ...draft, wireGuardSecretKey })} error={!draft.wireGuardSecretKey.trim() ? "WireGuard private key is required." : undefined} revealable />
                      <SecretField label="Peer public key" value={draft.wireGuardPeerPublicKey} onChange={(wireGuardPeerPublicKey) => setDraft({ ...draft, wireGuardPeerPublicKey })} error={!draft.wireGuardPeerPublicKey.trim() ? "Peer public key is required." : undefined} revealable />
                      <SecretField label="Preshared key" value={draft.wireGuardPreSharedKey} onChange={(wireGuardPreSharedKey) => setDraft({ ...draft, wireGuardPreSharedKey })} revealable />
                      <TextField label="Local addresses" value={draft.wireGuardLocalAddresses} onChange={(wireGuardLocalAddresses) => setDraft({ ...draft, wireGuardLocalAddresses })} placeholder="10.0.0.2/32, fd00::2/128" />
                      <TextField label="Allowed IPs" value={draft.wireGuardAllowedIps} onChange={(wireGuardAllowedIps) => setDraft({ ...draft, wireGuardAllowedIps })} placeholder="0.0.0.0/0, ::/0" />
                      <NumberField label="Keepalive" value={draft.wireGuardKeepAlive} min={0} onChange={(wireGuardKeepAlive) => setDraft({ ...draft, wireGuardKeepAlive })} />
                      <NumberField label="MTU" value={draft.wireGuardMtu} min={0} onChange={(wireGuardMtu) => setDraft({ ...draft, wireGuardMtu })} />
                      <TextField label="Reserved bytes" value={draft.wireGuardReserved} onChange={(wireGuardReserved) => setDraft({ ...draft, wireGuardReserved })} placeholder="1, 2, 3" />
                      <ToggleField label="Disable kernel TUN" checked={draft.wireGuardNoKernelTun} onChange={(wireGuardNoKernelTun) => setDraft({ ...draft, wireGuardNoKernelTun })} />
                      <SelectField
                        label="Domain strategy"
                        value={draft.wireGuardDomainStrategy || "ForceIP"}
                        onChange={(wireGuardDomainStrategy) => setDraft({ ...draft, wireGuardDomainStrategy: String(wireGuardDomainStrategy) })}
                        options={[
                          ["ForceIP", "ForceIP"],
                          ["ForceIPv4", "ForceIPv4"],
                          ["ForceIPv6", "ForceIPv6"],
                          ["ForceIPv4v6", "ForceIPv4v6"],
                          ["ForceIPv6v4", "ForceIPv6v4"],
                        ]}
                      />
                    </>
                  ) : (
                    <>
                      <TextField label="Username" value={draft.username} onChange={(username) => setDraft({ ...draft, username })} />
                      <SecretField label="Password" value={draft.password} onChange={(password) => setDraft({ ...draft, password })} revealable />
                    </>
                  )}
                  {draft.protocol === "vmess" && (
                    <>
                      <NumberField label="Alter ID" value={draft.alterId} min={0} onChange={(alterId) => setDraft({ ...draft, alterId })} />
                      <TextField label="Security" value={draft.security} onChange={(security) => setDraft({ ...draft, security })} placeholder="auto" />
                    </>
                  )}
                  {draft.protocol === "vless" && (
                    <SelectField
                      label="Flow"
                      value={draft.flow || v2rayFlowNoneValue}
                      onChange={(flow) => setDraft({ ...draft, flow: flow === v2rayFlowNoneValue ? "" : String(flow) })}
                      options={v2rayFlowOptions(draft.flow)}
                    />
                  )}
                  {(draft.protocol === "vless" || draft.protocol === "vmess") && (
                    <TextField label="Packet encoding" value={draft.packetEncoding} onChange={(packetEncoding) => setDraft({ ...draft, packetEncoding })} placeholder="xudp" />
                  )}
                  {draft.protocol === "http" && (
                    <TextField label="Headers JSON" value={draft.httpHeaders} onChange={(httpHeaders) => setDraft({ ...draft, httpHeaders })} placeholder='{"User-Agent":"Mozilla/5.0"}' />
                  )}
                </FieldGroup>
              </FieldSet>

              {draft.protocol !== "wireguard" && draft.protocol !== "shadowsocks" && draft.protocol !== "socks" && (
                <FieldSet>
                  <FieldTitle className="text-base">TLS and transport</FieldTitle>
                  <Separator />
                  <FieldGroup className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                    {(draft.protocol === "vless" || draft.protocol === "vmess" || draft.protocol === "trojan") && (
                      <SelectField
                        label="Network"
                        value={draft.network || "tcp"}
                        onChange={(network) => setDraft({ ...draft, network: String(network) })}
                        options={v2rayNetworkOptions}
                      />
                    )}
                  <ToggleField label="TLS" checked={draft.tls} onChange={(tls) => setDraft({ ...draft, tls })} />
                  <ToggleField label="Allow insecure certs" checked={draft.allowInsecure} onChange={(allowInsecure) => setDraft({ ...draft, allowInsecure })} />
                  <TextField label="SNI" value={draft.sni} onChange={(sni) => setDraft({ ...draft, sni })} placeholder={draft.server || "example.com"} />
                  <TextField label="ALPN" value={draft.alpn} onChange={(alpn) => setDraft({ ...draft, alpn })} placeholder="h2,http/1.1" />
                  <TextField label="uTLS fingerprint" value={draft.utlsFingerprint} onChange={(utlsFingerprint) => setDraft({ ...draft, utlsFingerprint })} placeholder="chrome" />
                  {!draft.reality && (
                    <TextField label="ECH config list" value={draft.echConfigList} onChange={(echConfigList) => setDraft({ ...draft, echConfigList })} placeholder="ip.gs+udp://8.8.8.8" />
                  )}
                  {draft.protocol === "vless" && (
                    <ToggleField label="Reality" checked={draft.reality} onChange={(reality) => setDraft({ ...draft, reality, tls: reality ? true : draft.tls })} />
                  )}
                  {draft.reality && (
                    <>
                      <TextField label="Reality public key" value={draft.realityPublicKey} onChange={(realityPublicKey) => setDraft({ ...draft, realityPublicKey })} />
                      <TextField label="Reality short ID" value={draft.realityShortId} onChange={(realityShortId) => setDraft({ ...draft, realityShortId })} />
                    </>
                  )}
                  {(draft.network === "ws" || draft.network === "http" || draft.network === "httpupgrade" || draft.network === "xhttp") && (
                    <>
                      <TextField label="Path" value={draft.transportPath} onChange={(transportPath) => setDraft({ ...draft, transportPath })} placeholder="/" />
                      <TextField label="Host header" value={draft.transportHost} onChange={(transportHost) => setDraft({ ...draft, transportHost })} />
                    </>
                  )}
                  {draft.network === "xhttp" && (
                    <>
                      <TextField label="XHTTP mode" value={draft.xhttpMode} onChange={(xhttpMode) => setDraft({ ...draft, xhttpMode })} placeholder="auto" />
                      <TextField label="XHTTP extra" value={draft.xhttpExtra} onChange={(xhttpExtra) => setDraft({ ...draft, xhttpExtra })} placeholder='{"noGRPCHeader":false}' />
                    </>
                  )}
                  {draft.network === "ws" && (
                    <>
                      <NumberField label="WS early data" value={draft.webSocketEarlyData} min={0} onChange={(webSocketEarlyData) => setDraft({ ...draft, webSocketEarlyData })} />
                      <TextField label="Early data header" value={draft.webSocketEarlyDataHeader} onChange={(webSocketEarlyDataHeader) => setDraft({ ...draft, webSocketEarlyDataHeader })} placeholder="Sec-WebSocket-Protocol" />
                    </>
                  )}
                  {draft.network === "grpc" && (
                    <TextField label="Service name" value={draft.serviceName} onChange={(serviceName) => setDraft({ ...draft, serviceName })} />
                  )}
                  {draft.protocol === "hysteria2" && (
                    <TextField label="Masquerade JSON" value={draft.hysteriaMasquerade} onChange={(hysteriaMasquerade) => setDraft({ ...draft, hysteriaMasquerade })} placeholder='{"type":"string","content":"ok"}' />
                  )}
                  </FieldGroup>
                </FieldSet>
              )}

              <FieldSet>
                <FieldTitle className="text-base">Advanced Xray JSON</FieldTitle>
                <Separator />
                <FieldGroup className="grid gap-4 md:grid-cols-2">
                  <TextAreaField label="Outbound settings override" value={draft.outboundSettings} onChange={(outboundSettings) => setDraft({ ...draft, outboundSettings })} placeholder='{"level":0}' className="h-24 font-mono text-xs" />
                  {draft.protocol !== "wireguard" && (
                    <TextAreaField label="Stream settings override" value={draft.streamSettings} onChange={(streamSettings) => setDraft({ ...draft, streamSettings })} placeholder='{"sockopt":{}}' className="h-24 font-mono text-xs" />
                  )}
                </FieldGroup>
              </FieldSet>
            </div>
          </div>
          <DialogFooter className="sm:justify-between">
            {Boolean(draft.id) ? (
              <Button type="button" variant="destructive" onClick={deleteDraft} className="sm:mr-auto">
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

      <Dialog open={Boolean(shareDialog)} onOpenChange={(open) => !open && setShareDialog(null)}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>Share V2Ray Profile</DialogTitle>
            <DialogDescription>{shareDialog?.profile.name || "V2Ray Connection"}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 space-y-4 overflow-y-auto pr-1">
            <div className="flex justify-center">
              {shareDialog?.qrDataUrl ? (
                <img
                  src={shareDialog.qrDataUrl}
                  alt="V2Ray share QR code"
                  className="size-56 rounded-md border bg-white p-2"
                />
              ) : (
                <div className="grid size-56 place-items-center rounded-md border bg-muted text-center text-sm text-muted-foreground">
                  {shareDialog?.qrError || "QR code unavailable"}
                </div>
              )}
            </div>
            <Textarea
              readOnly
              value={shareDialog?.link || ""}
              className="h-28 min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setShareDialog(null)}>
              Close
            </Button>
            <Button type="button" onClick={copySharedProfileLink}>
              <Copy />
              {shareDialog?.copyStatus || "Copy"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] overflow-hidden sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Import V2Ray Profiles</DialogTitle>
            <DialogDescription>Paste VLESS, VMess, Trojan, Shadowsocks, Hysteria2, SOCKS, HTTP proxy links, or WireGuard config.</DialogDescription>
          </DialogHeader>
          <TextAreaField
            label="Profiles"
            value={importText}
            onChange={setImportText}
            placeholder={"vless://...\nvmess://...\ntrojan://...\nss://...\nhy2://...\nsocks5://...\n[Interface]\nPrivateKey = ..."}
            className="h-[min(45svh,18rem)] min-h-0 resize-none overflow-auto font-mono text-xs"
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              Cancel
            </Button>
            <Button disabled={importDisabled} onClick={importProfiles}>
              <Download />
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(exportText)} onOpenChange={(open) => !open && setExportText("")}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Export All V2Ray Profiles</DialogTitle>
            <DialogDescription>Copy these profile links or WireGuard configs for import on another device.</DialogDescription>
          </DialogHeader>
          <Textarea
            readOnly
            value={exportText}
            className="h-[min(45svh,18rem)] min-h-0 resize-none overflow-auto font-mono text-xs leading-relaxed [field-sizing:fixed]"
          />
          <DialogFooter>
            <Button type="button" onClick={() => navigator.clipboard?.writeText(exportText)}>
              <Copy />
              Copy links
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function V2RaySubscriptionsPage({
  state,
  ping,
  onForgetPingProfiles,
  onState,
  onError,
  onSuccess,
}: {
  state: AppState;
  ping: V2RayPingState;
  onForgetPingProfiles: (ids: string[]) => void;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
}) {
  const fallbackDraft = useMemo(() => defaultV2RaySubscriptionDraft(), []);
  const [draft, setDraft] = useState(fallbackDraft);
  const [editorOpen, setEditorOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<V2RaySubscription | null>(null);
  const [refreshingSubscriptionIds, setRefreshingSubscriptionIds] = useState<Record<string, boolean>>({});
  const profileIndex = useMemo(
    () => buildV2RayProfileIndex(state.v2rayProfiles, ping.results, ping.scanningIds),
    [ping.results, ping.scanningIds, state.v2rayProfiles]
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
      const managedIds = result.state.v2rayProfiles.filter((profile) => profile.subscriptionId === subscription.id).map((profile) => profile.id);
      const beforeManagedIds = profileIndex.subscriptionProfileIds[subscription.id] || [];
      onForgetPingProfiles(beforeManagedIds.filter((id) => !managedIds.includes(id)));
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
      onForgetPingProfiles(beforeManagedIds);
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
        eyebrow="V2Ray"
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
              <table className="w-full min-w-[800px] table-fixed text-left">
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
                    <th className="px-3 py-2 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {state.v2raySubscriptions.map((subscription) => {
                    const refreshing = Boolean(refreshingSubscriptionIds[subscription.id]);
                    const managedProfileIds = profileIndex.subscriptionProfileIds[subscription.id] || [];
                    const deleteDisabled =
                      profileSelectionLocked(state.runtime) &&
                      v2RayRuntimeActive(state) &&
                      managedProfileIds.includes(state.runtime.activeConnectionId);
                    return (
                      <tr
                        key={subscription.id}
                        role="button"
                        tabIndex={0}
                        className="cursor-pointer border-b text-sm transition-colors last:border-b-0 hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
                        onClick={() => openExistingSubscription(subscription)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            openExistingSubscription(subscription);
                          }
                        }}
                      >
                        <td className="min-w-0 px-3 py-3">
                          <span className="block truncate font-medium">{subscription.name || "V2Ray Subscription"}</span>
                        </td>
                        <td className="min-w-0 px-3 py-3">
                          <span className="block truncate font-mono text-xs">{subscription.url}</span>
                        </td>
                        <td className="px-3 py-3">
                          <Badge variant="secondary">{managedProfileIds.length || subscription.importedCount || 0}</Badge>
                        </td>
                        <td className="min-w-0 px-3 py-3">
                          <span className={cn("block truncate text-xs", subscription.lastError ? "text-destructive" : "text-muted-foreground")}>
                            {v2raySubscriptionStatusLabel(subscription)}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-right">
                          <div className="flex justify-end gap-1">
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
                              <TooltipContent>{deleteDisabled ? "Disconnect first" : "Delete subscription and related configs"}</TooltipContent>
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
              <Button type="button" variant="destructive" onClick={() => requestDeleteSubscription(draft)} className="sm:mr-auto">
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

function BulkActionMenuItem({
  children,
  disabled,
  destructive,
  onClick,
}: {
  children: ReactNode;
  disabled?: boolean;
  destructive?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={disabled}
      className={cn(
        "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm outline-none transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
        destructive
          ? "text-destructive hover:bg-destructive/10 focus-visible:bg-destructive/10"
          : "hover:bg-accent hover:text-accent-foreground focus-visible:bg-accent focus-visible:text-accent-foreground"
      )}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function v2rayPingBadgeClass(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "border-amber-300 bg-amber-100 text-amber-900 dark:border-amber-900/60 dark:bg-amber-500/20 dark:text-amber-200";
  }
  if (!result) {
    return "text-muted-foreground";
  }
  if (result.ok) {
    return "bg-emerald-600 text-white hover:bg-emerald-600 dark:bg-emerald-500 dark:text-emerald-950 dark:hover:bg-emerald-500";
  }
  return "bg-red-600/10 text-red-700 hover:bg-red-600/10 dark:bg-red-500/20 dark:text-red-300 dark:hover:bg-red-500/20";
}

function v2rayPingBadgeLabel(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "Scanning";
  }
  if (!result) {
    return "Not checked";
  }
  if (result.ok) {
    return `${result.latencyMs} ms`;
  }
  if (result.message === "Server is required") {
    return "No server";
  }
  if (result.message === "Valid server port is required") {
    return "Bad port";
  }
  return result.latencyMs > 0 ? `Failed ${result.latencyMs} ms` : "Failed";
}

function formatV2RayDelay(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "...";
  }
  if (!result) {
    return "-";
  }
  if (result.delayOk) {
    return `${result.realDelayMs || result.latencyMs} ms`;
  }
  if (result.delayMessage) {
    return "-1";
  }
  if (result.ok && result.latencyMs > 0 && !result.speedOk) {
    return `${result.latencyMs} ms`;
  }
  return "-";
}

function v2rayDelayClass(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "text-amber-600";
  }
  if (!result || (!result.delayOk && !result.delayMessage && !result.latencyMs)) {
    return "text-muted-foreground";
  }
  return result.delayOk || (result.ok && result.latencyMs > 0 && !result.speedOk) ? "text-emerald-600" : "text-red-600";
}

function formatV2RaySpeedResult(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "...";
  }
  if (!result) {
    return "-";
  }
  if (result.speedOk && result.downloadBytesPerSecond > 0) {
    return `${((result.downloadBytesPerSecond * 8) / 1_000_000).toFixed(1)} Mbps`;
  }
  if (result.speedMessage) {
    return "-1";
  }
  return "-";
}

function v2raySpeedClass(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "text-amber-600";
  }
  if (!result || (!result.speedOk && !result.speedMessage)) {
    return "text-muted-foreground";
  }
  return result.speedOk ? "text-emerald-600" : "text-red-600";
}

function v2rayPingSelectLabel(result?: V2RayPingResult, scanning = false): string {
  if (scanning) {
    return "Scanning";
  }
  if (!result) {
    return "No ping";
  }
  return v2rayPingBadgeLabel(result);
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

type V2RayFilterCounts = {
  status: Record<string, number>;
  type: Record<string, number>;
  subscription: Record<string, number>;
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

function buildV2RayFilterCounts(
  profiles: V2RayProfile[],
  results: Record<string, V2RayPingResult>,
  scanningIds: Record<string, boolean>,
  filters: V2RayProfileFilters
): V2RayFilterCounts {
  const counts: V2RayFilterCounts = {
    status: { all: 0, reachable: 0, failed: 0, unchecked: 0 },
    type: Object.fromEntries(v2rayProfileTypeFilterOptions.map(([filter]) => [filter, 0])),
    subscription: { [v2raySubscriptionFilterAll]: 0, [v2raySubscriptionFilterManual]: 0 },
  };

  profiles.forEach((profile) => {
    const result = results[profile.id];
    const scanning = Boolean(scanningIds[profile.id]);
    const protocol = normalizeV2RayProtocol(profile.protocol);
    const subscriptionKey = profile.subscriptionId || v2raySubscriptionFilterManual;
    const statusKey = v2rayProfileStatusCountKey(result, scanning);

    if ((filters.type === "all" || protocol === filters.type) && v2rayProfileMatchesSubscriptionFilter(profile, filters.subscriptionId)) {
      counts.status.all += 1;
      if (statusKey) {
        counts.status[statusKey] = (counts.status[statusKey] || 0) + 1;
      }
    }

    if (v2rayProfileMatchesStatusFilter(result, scanning, filters.status) && v2rayProfileMatchesSubscriptionFilter(profile, filters.subscriptionId)) {
      counts.type.all += 1;
      counts.type[protocol] = (counts.type[protocol] || 0) + 1;
    }

    if (v2rayProfileMatchesStatusFilter(result, scanning, filters.status) && (filters.type === "all" || protocol === filters.type)) {
      counts.subscription[v2raySubscriptionFilterAll] += 1;
      counts.subscription[subscriptionKey] = (counts.subscription[subscriptionKey] || 0) + 1;
    }
  });

  return counts;
}

function countSelectedIds(ids: string[], selectedIds: Set<string>): number {
  let count = 0;
  ids.forEach((id) => {
    if (selectedIds.has(id)) {
      count += 1;
    }
  });
  return count;
}

function isTextEntryKeyboardTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  if (target.isContentEditable || target.closest("[contenteditable='true'], [contenteditable=''], textarea, select, [role='textbox']")) {
    return true;
  }
  const input = target.closest("input");
  if (!(input instanceof HTMLInputElement)) {
    return false;
  }
  const nonTextTypes = new Set(["button", "checkbox", "radio", "range", "reset", "submit", "image"]);
  return !nonTextTypes.has(input.type.toLowerCase());
}

function v2rayProfileStatusCountKey(result: V2RayPingResult | undefined, scanning: boolean): V2RayStatusFilter | "" {
  if (result?.ok || result?.speedOk || result?.delayOk) {
    return "reachable";
  }
  if (result) {
    return "failed";
  }
  if (!scanning) {
    return "unchecked";
  }
  return "";
}

function sortV2RayProfilesByMetric(
  profiles: V2RayProfile[],
  results: Record<string, V2RayPingResult>,
  scanningIds: Record<string, boolean>,
  sort: V2RayProfileSort
): V2RayProfile[] {
  if (sort.column === "none" || sort.direction === "none") {
    return profiles;
  }
  return profiles
    .map((profile, index) => ({ profile, index }))
    .sort((left, right) => {
      const comparison = compareV2RayMetricSort(
        results[left.profile.id],
        Boolean(scanningIds[left.profile.id]),
        results[right.profile.id],
        Boolean(scanningIds[right.profile.id]),
        sort
      );
      return comparison || left.index - right.index;
    })
    .map((item) => item.profile);
}

function compareV2RayMetricSort(
  left?: V2RayPingResult,
  leftScanning = false,
  right?: V2RayPingResult,
  rightScanning = false,
  sort: V2RayProfileSort = { column: "delay", direction: "asc" }
): number {
  const leftGroup = sort.column === "speed" ? v2raySpeedSortGroup(left, leftScanning) : v2rayPingSortGroup(left, leftScanning);
  const rightGroup = sort.column === "speed" ? v2raySpeedSortGroup(right, rightScanning) : v2rayPingSortGroup(right, rightScanning);
  if (leftGroup !== rightGroup) {
    return leftGroup - rightGroup;
  }
  if (leftGroup === 0) {
    const delta = sort.column === "speed" ? v2raySpeedSortValue(left) - v2raySpeedSortValue(right) : v2rayDelaySortValue(left) - v2rayDelaySortValue(right);
    return sort.direction === "desc" ? -delta : delta;
  }
  return 0;
}

function v2rayPingSortGroup(result?: V2RayPingResult, scanning = false): number {
  if (result?.delayOk || (result?.ok && (result.latencyMs || 0) > 0)) {
    return 0;
  }
  if (result?.speedOk) {
    return 1;
  }
  if (scanning) {
    return 2;
  }
  if (result) {
    return 3;
  }
  return 4;
}

function v2rayDelaySortValue(result?: V2RayPingResult): number {
  return result?.realDelayMs || result?.latencyMs || Number.POSITIVE_INFINITY;
}

function v2raySpeedSortGroup(result?: V2RayPingResult, scanning = false): number {
  if (result?.speedOk) {
    return 0;
  }
  if (scanning) {
    return 1;
  }
  if (result?.delayOk || result?.ok) {
    return 2;
  }
  if (result) {
    return 3;
  }
  return 4;
}

function v2raySpeedSortValue(result?: V2RayPingResult): number {
  return result?.downloadBytesPerSecond || Number.NEGATIVE_INFINITY;
}

function filterV2RayProfiles(
  profiles: V2RayProfile[],
  results: Record<string, V2RayPingResult>,
  scanningIds: Record<string, boolean>,
  filters: V2RayProfileFilters
): V2RayProfile[] {
  if (filters.status === "all" && filters.type === "all" && filters.subscriptionId === v2raySubscriptionFilterAll) {
    return profiles;
  }
  return profiles.filter((profile) => v2rayProfileMatchesFilters(profile, results[profile.id], Boolean(scanningIds[profile.id]), filters));
}

function v2rayProfileMatchesFilters(profile: V2RayProfile, result: V2RayPingResult | undefined, scanning: boolean, filters: V2RayProfileFilters): boolean {
  return (
    v2rayProfileMatchesStatusFilter(result, scanning, filters.status) &&
    (filters.type === "all" || normalizeV2RayProtocol(profile.protocol) === filters.type) &&
    v2rayProfileMatchesSubscriptionFilter(profile, filters.subscriptionId)
  );
}

function v2rayProfileMatchesStatusFilter(result: V2RayPingResult | undefined, scanning: boolean, filter: V2RayStatusFilter): boolean {
  switch (filter) {
    case "reachable":
      return Boolean(result?.ok || result?.speedOk || result?.delayOk);
    case "failed":
      return Boolean(result && !result.ok && !result.speedOk && !result.delayOk);
    case "unchecked":
      return !result && !scanning;
    default:
      return true;
  }
}

function v2rayProfileMatchesSubscriptionFilter(profile: V2RayProfile, filter: string): boolean {
  if (filter === v2raySubscriptionFilterAll) {
    return true;
  }
  if (filter === v2raySubscriptionFilterManual) {
    return !profile.subscriptionId;
  }
  return profile.subscriptionId === filter;
}

function v2raySubscriptionFilterOptions(profileIndex: V2RayProfileIndex, subscriptions: V2RaySubscription[]): Array<[string, string]> {
  const options: Array<[string, string]> = [[v2raySubscriptionFilterAll, "All subs"]];
  const knownSubscriptionIds = new Set<string>();
  if (profileIndex.manualProfileCount > 0) {
    options.push([v2raySubscriptionFilterManual, "Manual"]);
  }
  subscriptions.forEach((subscription) => {
    if (!subscription.id) {
      return;
    }
    knownSubscriptionIds.add(subscription.id);
    options.push([subscription.id, v2raySubscriptionFilterLabel(subscription)]);
  });
  Object.keys(profileIndex.subscriptionProfileIds)
    .filter((id) => !knownSubscriptionIds.has(id))
    .sort((left, right) => left.localeCompare(right))
    .forEach((id) => options.push([id, `Unknown sub ${id}`]));
  return options;
}

function v2raySubscriptionFilterLabel(subscription: V2RaySubscription): string {
  return subscription.name.trim() || subscription.url.trim() || "V2Ray subscription";
}

function fastestReachableV2RayProfile(profiles: V2RayProfile[], results: Record<string, V2RayPingResult>): V2RayProfile | undefined {
  return profiles.reduce<V2RayProfile | undefined>((fastest, profile) => {
    const result = results[profile.id];
    if (!result?.delayOk && !(result?.ok && result.latencyMs > 0)) {
      return fastest;
    }
    if (!fastest) {
      return profile;
    }
    const fastestResult = results[fastest.id];
    return v2rayDelaySortValue(result) < v2rayDelaySortValue(fastestResult) ? profile : fastest;
  }, undefined);
}

function isConnectableV2RayProfile(profile: V2RayProfile): boolean {
  if (!profile.server.trim()) {
    return false;
  }
  return v2rayProfileCredentialReady(profile);
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

function formatV2RayServerEndpoint(profile: V2RayProfile): string {
  const server = profile.server.trim();
  if (!server) {
    return "No server";
  }
  const port = profile.serverPort || 443;
  if (server.includes(":") && !server.startsWith("[")) {
    return `[${server}]:${port}`;
  }
  return `${server}:${port}`;
}

function formatV2RayCheckedAt(value?: number, scanning = false): string {
  if (scanning) {
    return "Checking";
  }
  if (!value) {
    return "Unchecked";
  }
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
  if (elapsedSeconds < 60) {
    return "Just now";
  }
  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  if (elapsedMinutes < 60) {
    return `${elapsedMinutes}m ago`;
  }
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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

function defaultV2RayDraft(): V2RayProfile {
  return {
    id: "",
    name: "V2Ray Connection",
    subscriptionId: "",
    protocol: "vless",
    server: "",
    serverPort: 443,
    uuid: "",
    password: "",
    alterId: 0,
    security: "auto",
    flow: "",
    packetEncoding: "",
    network: "tcp",
    tls: true,
    sni: "",
    alpn: "",
    allowInsecure: false,
    utlsFingerprint: "",
    echConfigList: "",
    reality: false,
    realityPublicKey: "",
    realityShortId: "",
    transportPath: "",
    transportHost: "",
    serviceName: "",
    xhttpMode: "",
    xhttpExtra: "",
    webSocketEarlyData: 0,
    webSocketEarlyDataHeader: "",
    username: "",
    shadowsocksMethod: "2022-blake3-aes-256-gcm",
    uot: false,
    uotVersion: 2,
    hysteriaAuth: "",
    hysteriaUdpIdleTimeout: 60,
    hysteriaMasquerade: "",
    httpHeaders: "",
    wireGuardSecretKey: "",
    wireGuardLocalAddresses: "10.0.0.2/32",
    wireGuardPeerPublicKey: "",
    wireGuardPreSharedKey: "",
    wireGuardAllowedIps: "0.0.0.0/0, ::/0",
    wireGuardKeepAlive: 0,
    wireGuardMtu: 1420,
    wireGuardReserved: "",
    wireGuardNoKernelTun: true,
    wireGuardDomainStrategy: "ForceIP",
    outboundSettings: "",
    streamSettings: "",
  };
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
        eyebrow="V2Ray"
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
            <table className="w-full min-w-[1040px] table-fixed text-left">
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
              <Button type="button" variant="destructive" onClick={deleteDraft} className="sm:mr-auto">
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

function V2RayLanConnectionBox({
  enabled,
  disabled,
  saving,
  runtimeBusy,
  systemIp,
  status,
  listenPort,
  inboundType,
  localEndpoint,
  lanEndpoint,
  copyStatus,
  onCopyEndpoint,
  onChange,
}: {
  enabled: boolean;
  disabled: boolean;
  saving: boolean;
  runtimeBusy: boolean;
  systemIp: string;
  status: LanIpStatus;
  listenPort: number;
  inboundType: string;
  localEndpoint: string;
  lanEndpoint: string;
  copyStatus: string;
  onCopyEndpoint: () => void;
  onChange: (enabled: boolean) => void | Promise<void>;
}) {
  const systemIpLabel = systemIp || (status === "loading" ? "Detecting..." : "Not detected");
  const lanEndpointLabel = lanEndpoint || (status === "loading" ? "Detecting..." : `LAN IP:${listenPort}`);
  const inboundLabel = v2rayInboundLabel(inboundType);
  const guideSteps = [
    {
      icon: <Monitor />,
      title: "This computer",
      body: `WhiteDNS opens ${inboundLabel} on every network interface.`,
      value: localEndpoint || `127.0.0.1:${listenPort}`,
    },
    {
      icon: <Wifi />,
      title: "System LAN IP",
      body: "Other devices on the same Wi-Fi or Ethernet network use this host.",
      value: systemIpLabel,
    },
    {
      icon: <Network />,
      title: "Device proxy",
      body: "Set manual proxy host and port on the phone, tablet, or computer.",
      value: lanEndpointLabel,
    },
  ];

  return (
    <div className={cn("rounded-lg border bg-background/70 p-4", enabled && "border-primary/30 bg-primary/5")}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="inline-flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Share2 className="size-4" />
            </span>
            <div>
              <p className="text-sm font-semibold">Allow LAN connection</p>
              <p className="text-xs text-muted-foreground">{enabled ? "Visible to devices on this network" : "Only this computer can use the proxy"}</p>
            </div>
          </div>
        </div>
        <Switch checked={enabled} disabled={disabled} onCheckedChange={(checked) => void onChange(checked)} aria-label="Allow LAN connection" />
      </div>

      {enabled && (
        <div className="mt-4 border-t pt-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-semibold">LAN sharing guide</p>
              <p className="text-xs text-muted-foreground">Use this address on other devices after saving and connecting V2Ray.</p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <Badge variant="outline" className="font-mono">
                {lanEndpointLabel}
              </Badge>
              <Button type="button" size="sm" variant="outline" disabled={!lanEndpoint} onClick={onCopyEndpoint}>
                <Copy />
                Copy address
              </Button>
              {copyStatus && <span className="text-xs font-medium text-muted-foreground">{copyStatus}</span>}
            </div>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            {guideSteps.map((step) => (
              <div key={step.title} className="flex min-w-0 gap-3">
                <span className="mt-0.5 inline-flex size-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
                  {step.icon}
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{step.title}</p>
                  <p className="mt-1 break-all font-mono text-sm">{step.value}</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">{step.body}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 grid gap-3 border-t pt-3 md:grid-cols-2">
            <div className="flex gap-2 text-xs leading-5 text-muted-foreground">
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
              <span>On the other device, choose manual proxy, enter host <span className="font-mono text-foreground">{systemIpLabel}</span>, and port <span className="font-mono text-foreground">{listenPort}</span>.</span>
            </div>
            <div className="flex gap-2 text-xs leading-5 text-muted-foreground">
              <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-600" />
              <span>
                {runtimeBusy
                  ? "Disconnect before changing LAN access."
                  : saving
                    ? "Saving LAN access..."
                    : <>Keep this enabled only on trusted networks. Your firewall must allow inbound connections to port <span className="font-mono text-foreground">{listenPort}</span>.</>}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
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

function withV2RaySettingsAllowLan(profile: V2RaySettingsProfile, allowLan: boolean): V2RaySettingsProfile {
  return {
    ...profile,
    allowLan,
    listenIp: allowLan ? "0.0.0.0" : v2rayListenAllowsLan(profile.listenIp) ? "127.0.0.1" : profile.listenIp || "127.0.0.1",
  };
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

function v2rayProtocolLabel(protocol: string): string {
  switch (normalizeV2RayProtocol(protocol)) {
    case "vmess":
      return "VMess";
    case "trojan":
      return "Trojan";
    case "shadowsocks":
      return "Shadowsocks";
    case "hysteria2":
      return "Hysteria2";
    case "wireguard":
      return "WireGuard";
    case "socks":
      return "SOCKS";
    case "http":
      return "HTTP";
    default:
      return "VLESS";
  }
}

function v2rayNetworkLabel(network: string): string {
  const match = v2rayNetworkOptions.find(([value]) => value === (network || "tcp"));
  return match?.[1] || (network || "tcp").toUpperCase();
}

function v2rayFlowOptions(currentFlow: string): Array<[string, string]> {
  const flow = currentFlow.trim();
  if (!flow || v2rayBaseFlowOptions.some(([value]) => value === flow)) {
    return v2rayBaseFlowOptions;
  }
  return [...v2rayBaseFlowOptions, [flow, flow]];
}

function isExportableV2RayProfile(profile: V2RayProfile): boolean {
  if (!profile.server.trim()) {
    return false;
  }
  return v2rayProfileCredentialReady(profile);
}

function ResolversPage({
  state,
  validation,
  onState,
  onError,
}: {
  state: AppState;
  validation: ResolverTextValidation;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const isProfileLocked = profileSelectionLocked(state.runtime);
  const activeResolverId = effectiveResolverProfileId(state);
  const activeResolver = state.resolverProfiles.find((profile) => profile.id === activeResolverId) || state.resolverProfiles[0];
  const selected = activeResolver || state.resolverProfiles[0];
  const [draft, setDraft] = useState(selected);
  const [editorOpen, setEditorOpen] = useState(false);
  const [draftValidation, setDraftValidation] = useState(validation);
  const [previewOffset, setPreviewOffset] = useState(0);
  const [previewPage, setPreviewPage] = useState<ResolverPreviewPage | null>(null);
  const draftIsFileBacked = isFileBackedResolver(draft);

  useEffect(() => {
    if (!editorOpen) {
      setDraft(selected);
      setPreviewOffset(0);
    }
  }, [editorOpen, selected]);

  useEffect(() => {
    if (draftIsFileBacked) {
      setDraftValidation(validationFromFileBackedResolver(draft));
      return;
    }
    backend.validateResolverText(draft.resolverText).then(setDraftValidation).catch(() => setDraftValidation(defaultValidation));
  }, [draft.resolverText, draft.resolverSource, draft.resolverCount]);

  useEffect(() => {
    if (!draftIsFileBacked || !draft.id) {
      setPreviewPage(null);
      return;
    }
    backend
      .getResolverProfilePreview(draft.id, previewOffset, resolverPreviewPageSize)
      .then(setPreviewPage)
      .catch(() => setPreviewPage(null));
  }, [draft.id, draftIsFileBacked, previewOffset]);

  async function saveResolverDraft() {
    onError("");
    const profile = draft.id ? draft : { ...draft, id: makeResolverProfileId(state.resolverProfiles) };
    try {
      const nextState = await backend.saveResolverProfile(profile);
      onState(nextState);
      const savedProfile = nextState.resolverProfiles.find((candidate) => candidate.id === profile.id) || profile;
      setDraft(savedProfile);
      setEditorOpen(false);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function deleteResolverDraft() {
    const deletedResolverId = draft.id;
    if (!deletedResolverId) {
      return;
    }
    onError("");
    try {
      const nextState = await backend.deleteResolverProfile(deletedResolverId);
      onState(nextState);
      setEditorOpen(false);
      const nextActiveResolverId = effectiveResolverProfileId(nextState);
      setDraft(nextState.resolverProfiles.find((profile) => profile.id === nextActiveResolverId) || nextState.resolverProfiles[0]);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  function openResolverProfile(profile: ResolverProfile) {
    onError("");
    setDraft(profile);
    setPreviewOffset(0);
    setEditorOpen(true);
    if (isProfileLocked) {
      return;
    }
    backend.selectResolverProfile(profile.id).then(onState).catch((err) => onError(messageFromError(err)));
  }

  function openNewResolverProfile() {
    onError("");
    setDraft({ id: "", name: "Resolvers", resolverText: "" });
    setPreviewOffset(0);
    setEditorOpen(true);
  }

  async function importResolverFile() {
    onError("");
    try {
      const result = await backend.importResolverProfileFile();
      onState(result.state);
      if (result.profile.id) {
        setDraft(result.profile);
        setPreviewOffset(0);
        setEditorOpen(true);
      }
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  return (
    <>
      <PageShell
        eyebrow="Resolvers"
        title="Resolver Profiles"
        actions={
          <>
            <Button variant="outline" onClick={importResolverFile}>
              <Upload />
              Import file
            </Button>
            <Button variant="outline" onClick={openNewResolverProfile}>
              <Plus />
              New
            </Button>
          </>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
            <div className="min-w-0">
              <p className="text-sm font-semibold">Resolver profiles</p>
              <p className="text-xs text-muted-foreground">
                {state.resolverProfiles.length} profile{state.resolverProfiles.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[780px] table-fixed text-left">
              <colgroup>
                <col className="w-[27%]" />
                <col className="w-[13%]" />
                <col className="w-[14%]" />
                <col className="w-[12%]" />
                <col className="w-[34%]" />
              </colgroup>
              <thead className="border-b bg-muted/20 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Source</th>
                  <th className="px-3 py-2 font-medium">Resolvers</th>
                  <th className="px-3 py-2 font-medium">Invalid</th>
                  <th className="px-3 py-2 font-medium">Preview</th>
                </tr>
              </thead>
              <tbody>
                {state.resolverProfiles.map((profile) => {
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
                      onClick={() => openResolverProfile(profile)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          openResolverProfile(profile);
                        }
                      }}
                    >
                      <td className="min-w-0 px-3 py-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="truncate font-medium">{profile.name || "Resolvers"}</span>
                          {selectedProfile && (
                            <Badge variant="outline" className="shrink-0">
                              Selected
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant="secondary">{isFileBackedResolver(profile) ? "File" : "Text"}</Badge>
                      </td>
                      <td className="px-3 py-3 tabular-nums">{resolverProfileCount(profile)}</td>
                      <td className="px-3 py-3 tabular-nums">{profile.resolverInvalidCount || 0}</td>
                      <td className="min-w-0 px-3 py-3">
                        <span className="block truncate font-mono text-xs">{resolverProfilePreviewLabel(profile)}</span>
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
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-6xl">
          <DialogHeader>
            <DialogTitle>{draft.id ? draft.name : "New resolver profile"}</DialogTitle>
            <DialogDescription>DNS route pool</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto pr-1">
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_280px]">
              <div className="min-w-0">
                <FieldGroup>
                  <TextField label="Name" value={draft.name} onChange={(name) => setDraft({ ...draft, name })} />
                  {draftIsFileBacked ? (
                    <div className="rounded-lg border bg-muted/25 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm font-medium">{displayFileName(draft.resolverFile)}</p>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {draft.resolverCount || 0} normalized resolvers
                            {draft.resolverInvalidCount ? `, ${draft.resolverInvalidCount} skipped` : ""}
                          </p>
                        </div>
                        <Badge variant="outline">File-backed</Badge>
                      </div>
                      <Separator className="my-4" />
                      <ResolverFilePreview
                        page={previewPage}
                        fallback={draft.resolverPreview || []}
                        onPrevious={() => setPreviewOffset(Math.max(0, previewOffset - resolverPreviewPageSize))}
                        onNext={() => setPreviewOffset(previewOffset + resolverPreviewPageSize)}
                      />
                    </div>
                  ) : (
                    <TextAreaField
                      label="Resolvers"
                      value={draft.resolverText}
                      onChange={(resolverText) => setDraft({ ...draft, resolverText })}
                      placeholder={"1.1.1.1\n8.8.8.8:53\n[2606:4700:4700::1111]:53"}
                      className="h-[min(28rem,calc(100svh-24rem))] min-h-72 max-h-[28rem] resize-none overflow-y-auto font-mono text-sm"
                    />
                  )}
                </FieldGroup>
              </div>

              <Card className={draftValidation.isValid ? "border-emerald-200" : "border-amber-200"}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {draftValidation.isValid ? <CheckCircle2 className="size-4 text-emerald-600" /> : <AlertCircle className="size-4 text-amber-600" />}
                    Validation
                  </CardTitle>
                  <CardDescription>
                    {draftValidation.isValid ? "Resolver profile is ready." : "Resolve issues before saving."}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <Metric label="Normalized" value={`${draftIsFileBacked ? draft.resolverCount || 0 : draftValidation.normalizedResolvers.length}`} compact />
                  <Metric label="Invalid" value={`${draftIsFileBacked ? draft.resolverInvalidCount || 0 : draftValidation.invalidEntries.length}`} compact />
                  {draftValidation.isValid ? (
                    <Alert className="border-emerald-200 bg-emerald-50 text-emerald-950">
                      <CheckCircle2 />
                      <AlertTitle>Valid resolver list</AlertTitle>
                    </Alert>
                  ) : (
                    <Alert className="border-amber-200 bg-amber-50 text-amber-950">
                      <AlertCircle />
                      <AlertTitle>Validation required</AlertTitle>
                      <AlertDescription>
                        {draftValidation.invalidEntries.length
                          ? `Invalid entries: ${draftValidation.invalidEntries.join(", ")}`
                          : "At least one resolver is required."}
                      </AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
          <DialogFooter className="sm:justify-between">
            {draft.id !== "resolver-default" && Boolean(draft.id) ? (
              <Button type="button" variant="destructive" onClick={deleteResolverDraft} className="sm:mr-auto">
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
              <Button type="button" onClick={saveResolverDraft}>
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

function SettingsPage({
  state,
  section,
  onSection,
  onState,
  onError,
  onSuccess,
  onToml,
}: {
  state: AppState;
  section: SettingsSection;
  onSection: (section: SettingsSection) => void;
  onState: (state: AppState) => void;
  onError: (message: string) => void;
  onSuccess: (message: string) => void;
  onToml: (toml: string) => void;
}) {
  const selected = state.settingsProfiles.find((profile) => profile.id === state.selectedSettingsProfileId) || state.settingsProfiles[0];
  const [draft, setDraft] = useState(selected);
  const [editorOpen, setEditorOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importName, setImportName] = useState("Imported settings");
  const [importType, setImportType] = useState<ImportType>("masterdns");
  const importDisabled = !importText.trim();
  const defaultSettingsDraft = draft.id === "settings-default";

  useEffect(() => {
    if (!editorOpen) {
      setDraft(selected);
    }
  }, [editorOpen, selected]);

  async function exportToml() {
    onError("");
    try {
      onToml(await backend.exportSettingsProfileToml(editorOpen ? draft : selected));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function resetDraftToDefaults() {
    onError("");
    try {
      const defaults = await backend.getDefaultSettingsProfile();
      setDraft({ ...defaults, id: draft.id, name: draft.name || defaults.name });
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function importTomlFile(file: File | null) {
    if (!file) {
      return;
    }
    setImportText(await file.text());
    const name = file.name.replace(/\.[^/.]+$/, "").trim();
    if (name) {
      setImportName(name);
    }
  }

  async function importToml() {
    onError("");
    try {
      const next = await backend.importSettingsProfileToml(importText, importName, importType);
      onState(next);
      setImportText("");
      setImportName("Imported settings");
      setImportType("masterdns");
      setImportOpen(false);
      onSuccess("Imported settings profile.");
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function saveSettingsDraft() {
    onError("");
    try {
      const nextState = await backend.saveSettingsProfile(draft);
      onState(nextState);
      const savedProfile = nextState.settingsProfiles.find((candidate) => candidate.id === draft.id) ||
        nextState.settingsProfiles.find((candidate) => candidate.id === nextState.selectedSettingsProfileId) ||
        draft;
      setDraft(savedProfile);
      setEditorOpen(false);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function deleteSettingsDraft() {
    if (!draft.id) {
      return;
    }
    onError("");
    try {
      const nextState = await backend.deleteSettingsProfile(draft.id);
      onState(nextState);
      setEditorOpen(false);
      setDraft(nextState.settingsProfiles.find((profile) => profile.id === nextState.selectedSettingsProfileId) || nextState.settingsProfiles[0]);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  function openSettingsProfile(profile: SettingsProfile) {
    onError("");
    setDraft(profile);
    setEditorOpen(true);
    backend.selectSettingsProfile(profile.id).then(onState).catch((err) => onError(messageFromError(err)));
  }

  function openNewSettingsProfile() {
    onError("");
    setDraft({ ...draft, id: "", name: "Settings", importType: draft.importType || "masterdns" });
    setEditorOpen(true);
  }

  return (
    <>
      <PageShell
        eyebrow="Settings"
        title="Runtime Settings"
        actions={
          <>
            <Button variant="outline" onClick={exportToml}>
              <FileText />
              Export TOML
            </Button>
            <Button variant="outline" onClick={() => setImportOpen(true)}>
              <Upload />
              Import
            </Button>
            <Button variant="outline" onClick={openNewSettingsProfile}>
              <Plus />
              New
            </Button>
          </>
        }
      >
        <div className="overflow-hidden rounded-lg border bg-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2.5">
            <div className="min-w-0">
              <p className="text-sm font-semibold">Settings profiles</p>
              <p className="text-xs text-muted-foreground">
                {state.settingsProfiles.length} profile{state.settingsProfiles.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] table-fixed text-left">
              <colgroup>
                <col className="w-[25%]" />
                <col className="w-[12%]" />
                <col className="w-[18%]" />
                <col className="w-[21%]" />
                <col className="w-[14%]" />
                <col className="w-[10%]" />
              </colgroup>
              <thead className="border-b bg-muted/20 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Type</th>
                  <th className="px-3 py-2 font-medium">Proxy</th>
                  <th className="px-3 py-2 font-medium">MTU</th>
                  <th className="px-3 py-2 font-medium">Traffic</th>
                  <th className="px-3 py-2 font-medium">Log</th>
                </tr>
              </thead>
              <tbody>
                {state.settingsProfiles.map((profile) => {
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
                          <span className="truncate font-medium">{profile.name || "Settings"}</span>
                          {selectedProfile && (
                            <Badge variant="outline" className="shrink-0">
                              Selected
                            </Badge>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant="secondary">{importTypeLabel(profile.importType)}</Badge>
                      </td>
                      <td className="min-w-0 px-3 py-3">
                        <span className="block truncate font-mono text-xs">{proxyEndpoint(profile.listenIp, profile.listenPort)}</span>
                      </td>
                      <td className="min-w-0 px-3 py-3">
                        <span className="block truncate font-mono text-xs">
                          U {profile.minUploadMtu}-{profile.maxUploadMtu} · D {profile.minDownloadMtu}-{profile.maxDownloadMtu}
                        </span>
                      </td>
                      <td className="px-3 py-3 font-mono text-xs">
                        U{profile.uploadDuplication} / D{profile.downloadDuplication}
                      </td>
                      <td className="px-3 py-3 uppercase">{profile.logLevel || "WARN"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </PageShell>

      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-6xl">
          <DialogHeader>
            <DialogTitle>{draft.id ? draft.name : "New settings profile"}</DialogTitle>
            <DialogDescription>{sectionLabel(section)}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 overflow-y-auto pr-1">
            <Tabs value={section} onValueChange={(value) => onSection(value as SettingsSection)} className="min-h-0 gap-4">
              <TabsList className="flex h-auto flex-wrap justify-start">
                {settingsSections.map((item) => (
                  <TabsTrigger key={item.id} value={item.id} className="gap-1.5">
                    {item.icon}
                    {item.label}
                  </TabsTrigger>
                ))}
              </TabsList>
              {settingsSections.map((item) => (
                <TabsContent key={item.id} value={item.id} className="mt-0 min-h-0">
                  <SettingsFields section={item.id} draft={draft} onDraft={setDraft} />
                </TabsContent>
              ))}
            </Tabs>
          </div>
          <DialogFooter className="sm:justify-between">
            {draft.id !== "settings-default" && Boolean(draft.id) ? (
              <Button type="button" variant="destructive" onClick={deleteSettingsDraft} className="sm:mr-auto">
                <Trash2 />
                Delete
              </Button>
            ) : (
              <span />
            )}
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button type="button" variant="outline" onClick={resetDraftToDefaults}>
                <RotateCcw />
                Reset defaults
              </Button>
              <Button type="button" variant="outline" onClick={() => setEditorOpen(false)}>
                Cancel
              </Button>
              <Button type="button" disabled={defaultSettingsDraft} title={defaultSettingsDraft ? "Create a new profile to save changes" : undefined} onClick={saveSettingsDraft}>
                <Save />
                Save
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Import Settings TOML</DialogTitle>
            <DialogDescription>Select a TOML file or paste exported settings.</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 space-y-4 overflow-auto pr-1">
            <Field>
              <FieldLabel>TOML file</FieldLabel>
              <Input type="file" accept=".toml,text/plain" onChange={(event) => importTomlFile(event.target.files?.[0] || null)} />
            </Field>
            <TextField label="Profile name" value={importName} onChange={setImportName} />
            <SelectField
              label="Import type"
              value={importType}
              onChange={setImportType}
              options={importTypeOptions}
              description="Marker comments in exported TOML override this selection."
            />
            <TextAreaField
              label="TOML"
              value={importText}
              onChange={setImportText}
              placeholder={"LISTEN_IP = \"127.0.0.1\"\nLISTEN_PORT = 10887\nSOCKS5_AUTH = false"}
              className="h-[min(45svh,20rem)] min-h-0 resize-none overflow-auto font-mono text-xs"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              Cancel
            </Button>
            <Button disabled={importDisabled} onClick={importToml}>
              <Upload />
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
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
            <CardDescription>Export or restore all saved WhiteDNS profiles.</CardDescription>
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
            <DialogTitle>WhiteDNS backup.json</DialogTitle>
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

function SettingsFields({
  section,
  draft,
  onDraft,
}: {
  section: SettingsSection;
  draft: SettingsProfile;
  onDraft: (profile: SettingsProfile) => void;
}) {
  switch (section) {
    case "general":
      return (
        <SettingsFieldSet legend="General">
          <TextField label="Profile name" value={draft.name} onChange={(name) => onDraft({ ...draft, name })} />
          <SelectField
            label="Import type"
            value={normalizeImportType(draft.importType)}
            onChange={(nextImportType) => onDraft({ ...draft, importType: nextImportType })}
            options={importTypeOptions}
          />
          {normalizeImportType(draft.importType) === "stormdns" && (
            <SelectField
              label="Startup mode"
              value={draft.startupMode}
              onChange={(startupMode) => onDraft({ ...draft, startupMode: String(startupMode) })}
              options={[
                ["resolvers", "Full scan"],
                ["logs", "From logs"],
                ["ask", "Ask"],
              ]}
            />
          )}
          <SelectField
            label="Log level"
            value={draft.logLevel}
            onChange={(logLevel) => onDraft({ ...draft, logLevel: String(logLevel) })}
            options={[
              ["DEBUG", "DEBUG"],
              ["INFO", "INFO"],
              ["WARN", "WARN"],
              ["ERROR", "ERROR"],
            ]}
          />
          <ToggleField label="Base encode data" checked={draft.baseEncodeData} onChange={(baseEncodeData) => onDraft({ ...draft, baseEncodeData })} />
        </SettingsFieldSet>
      );
    case "proxy":
      return (
        <div className="space-y-6">
          <SettingsFieldSet legend="Public proxy">
            <SelectField
              label="Inbound type"
              value={draft.singBoxInboundType || "mixed"}
              onChange={(singBoxInboundType) =>
                onDraft({ ...draft, singBoxInboundType: String(singBoxInboundType), singBoxEnabled: true })
              }
              options={[
                ["mixed", "Mixed SOCKS/HTTP"],
                ["socks", "SOCKS"],
                ["http", "HTTP"],
              ]}
              description="Xray is always used as the public proxy core."
            />
            <ToggleField
              label="Set system proxy"
              checked={draft.singBoxSetSystemProxy}
              onChange={(singBoxSetSystemProxy) => onDraft({ ...draft, singBoxSetSystemProxy, singBoxEnabled: true })}
            />
            <TextField label="Public listen IP" value={draft.listenIp} onChange={(listenIp) => onDraft({ ...draft, listenIp })} />
            <NumberField label="Public proxy port" value={draft.listenPort} onChange={(listenPort) => onDraft({ ...draft, listenPort })} />
          </SettingsFieldSet>

          <SettingsFieldSet legend="MasterDNS/StormDNS upstream">
            <TextField
              label="MasterDNS/StormDNS listen IP"
              value={draft.stormDnsListenIp}
              onChange={(stormDnsListenIp) => onDraft({ ...draft, stormDnsListenIp })}
              description="Internal listener used behind Xray."
            />
            <NumberField
              label="MasterDNS/StormDNS listen port"
              value={draft.stormDnsListenPort}
              onChange={(stormDnsListenPort) => onDraft({ ...draft, stormDnsListenPort })}
            />
          </SettingsFieldSet>

          <SettingsFieldSet legend="Proxy access">
            <ToggleField label="Proxy authentication" checked={draft.socks5Authentication} onChange={(socks5Authentication) => onDraft({ ...draft, socks5Authentication })} />
            {draft.socks5Authentication && (
              <>
                <TextField label="Proxy user" value={draft.socksUsername} onChange={(socksUsername) => onDraft({ ...draft, socksUsername })} />
                <SecretField label="Proxy password" value={draft.socksPassword} onChange={(socksPassword) => onDraft({ ...draft, socksPassword })} />
              </>
            )}
            <NumberField label="Local handshake timeout" value={draft.localHandshakeTimeoutSeconds} step="0.1" onChange={(localHandshakeTimeoutSeconds) => onDraft({ ...draft, localHandshakeTimeoutSeconds })} />
            <NumberField label="UDP associate timeout" value={draft.socksUdpAssociateReadTimeoutSeconds} step="0.1" onChange={(socksUdpAssociateReadTimeoutSeconds) => onDraft({ ...draft, socksUdpAssociateReadTimeoutSeconds })} />
          </SettingsFieldSet>
        </div>
      );
    case "dns":
      return (
        <SettingsFieldSet legend="DNS">
          <ToggleField label="Local DNS" checked={draft.localDnsEnabled} onChange={(localDnsEnabled) => onDraft({ ...draft, localDnsEnabled })} />
          <NumberField label="Local DNS port" value={draft.localDnsPort} onChange={(localDnsPort) => onDraft({ ...draft, localDnsPort })} />
          <SelectField
            label="Balancing"
            value={draft.balancingStrategy}
            onChange={(balancingStrategy) => onDraft({ ...draft, balancingStrategy: Number(balancingStrategy) })}
            options={[
              [1, "Random"],
              [2, "Round Robin"],
              [3, "Least Loss"],
              [4, "Lowest Latency"],
              [5, "Hybrid Score"],
              [6, "Loss Then Latency"],
              [7, "Least Loss Top Random"],
              [8, "Least Loss Top Round Robin"],
            ]}
          />
          <NumberField label="Resolver UDP pool size" value={draft.resolverUdpConnectionPoolSize} onChange={(resolverUdpConnectionPoolSize) => onDraft({ ...draft, resolverUdpConnectionPoolSize })} />
        </SettingsFieldSet>
      );
    case "traffic":
      const isMasterDNS = normalizeImportType(draft.importType) === "masterdns";
      return (
        <SettingsFieldSet legend="Traffic">
          <NumberField label={isMasterDNS ? "Packet duplication" : "Upload duplication"} value={draft.uploadDuplication} min={isMasterDNS ? 0 : 1} max={isMasterDNS ? 10 : 90} onChange={(uploadDuplication) => onDraft({ ...draft, uploadDuplication })} />
          <NumberField label={isMasterDNS ? "Setup packet duplication" : "Download duplication"} value={draft.downloadDuplication} min={isMasterDNS ? 0 : 1} max={isMasterDNS ? 12 : 90} onChange={(downloadDuplication) => onDraft({ ...draft, downloadDuplication })} />
          <SelectField
            label="Upload compression"
            value={String(draft.uploadCompression)}
            onChange={(uploadCompression) => onDraft({ ...draft, uploadCompression: Number(uploadCompression) })}
            options={compressionOptions()}
          />
          <SelectField
            label="Download compression"
            value={String(draft.downloadCompression)}
            onChange={(downloadCompression) => onDraft({ ...draft, downloadCompression: Number(downloadCompression) })}
            options={compressionOptions()}
          />
        </SettingsFieldSet>
      );
    case "mtu":
      const masterMTU = normalizeImportType(draft.importType) === "masterdns";
      return (
        <SettingsFieldSet legend="MTU">
          <NumberField label="Min upload MTU" value={draft.minUploadMtu} onChange={(minUploadMtu) => onDraft({ ...draft, minUploadMtu })} />
          <NumberField label="Max upload MTU" value={draft.maxUploadMtu} onChange={(maxUploadMtu) => onDraft({ ...draft, maxUploadMtu })} />
          <NumberField label="Min download MTU" value={draft.minDownloadMtu} onChange={(minDownloadMtu) => onDraft({ ...draft, minDownloadMtu })} />
          <NumberField label="Max download MTU" value={draft.maxDownloadMtu} onChange={(maxDownloadMtu) => onDraft({ ...draft, maxDownloadMtu })} />
          <NumberField label={masterMTU ? "MTU test retries" : "Resolver test retries"} value={draft.mtuTestRetriesResolvers} onChange={(mtuTestRetriesResolvers) => onDraft({ ...draft, mtuTestRetriesResolvers })} />
          <NumberField label={masterMTU ? "MTU test timeout" : "Resolver test timeout"} value={draft.mtuTestTimeoutResolvers} step="0.1" onChange={(mtuTestTimeoutResolvers) => onDraft({ ...draft, mtuTestTimeoutResolvers })} />
          <NumberField label={masterMTU ? "MTU test parallelism" : "Resolver test parallelism"} value={draft.mtuTestParallelismResolvers} onChange={(mtuTestParallelismResolvers) => onDraft({ ...draft, mtuTestParallelismResolvers })} />
          <ToggleField
            label="Full MTU scan before connecting"
            checked={(draft.connectionStartupMode || "standard") === "full-scan"}
            description="Wait for every resolver MTU probe to complete before starting. Leave off for the standard MasterDNS early-start behavior."
            onChange={(checked) => onDraft({ ...draft, connectionStartupMode: checked ? "full-scan" : "standard" })}
          />
          {masterMTU && (
            <>
              <ToggleField
                label="Startup loss MTU verify"
                checked={draft.mtuStartupLossVerifyEnabled}
                description="After the proxy opens, run a conservative background loss check that only lowers MTU when needed."
                onChange={(mtuStartupLossVerifyEnabled) => onDraft({ ...draft, mtuStartupLossVerifyEnabled })}
              />
              <NumberField
                label="Startup loss samples"
                value={draft.mtuStartupLossVerifySamples}
                description="Probe repeats per candidate; more is steadier but slower."
                onChange={(mtuStartupLossVerifySamples) => onDraft({ ...draft, mtuStartupLossVerifySamples })}
              />
              <NumberField
                label="Startup max loss percent"
                value={draft.mtuStartupLossVerifyMaxLossPercent}
                description="Accepted startup probe loss; 34% with 3 samples allows 1 miss."
                onChange={(mtuStartupLossVerifyMaxLossPercent) => onDraft({ ...draft, mtuStartupLossVerifyMaxLossPercent })}
              />
              <NumberField
                label="Startup MTU candidates"
                value={draft.mtuStartupLossVerifyCandidates}
                description="MTU sizes to try; MasterDNS keeps the highest reliable one."
                onChange={(mtuStartupLossVerifyCandidates) => onDraft({ ...draft, mtuStartupLossVerifyCandidates })}
              />
              <ToggleField
                label="MTU recheck"
                checked={draft.mtuRecheckEnabled}
                description="Re-tests active resolver MTUs while connected and hot-applies changes."
                onChange={(mtuRecheckEnabled) => onDraft({ ...draft, mtuRecheckEnabled })}
              />
              <NumberField
                label="Recheck interval minutes"
                value={draft.mtuRecheckIntervalMinutes}
                description="Minutes between live rechecks; default 5."
                onChange={(mtuRecheckIntervalMinutes) => onDraft({ ...draft, mtuRecheckIntervalMinutes })}
              />
            </>
          )}
          {!masterMTU && (
            <>
              <NumberField label="Log test retries" value={draft.mtuTestRetriesLogs} onChange={(mtuTestRetriesLogs) => onDraft({ ...draft, mtuTestRetriesLogs })} />
              <NumberField label="Log test timeout" value={draft.mtuTestTimeoutLogs} step="0.1" onChange={(mtuTestTimeoutLogs) => onDraft({ ...draft, mtuTestTimeoutLogs })} />
              <NumberField label="Log test parallelism" value={draft.mtuTestParallelismLogs} onChange={(mtuTestParallelismLogs) => onDraft({ ...draft, mtuTestParallelismLogs })} />
            </>
          )}
        </SettingsFieldSet>
      );
    case "performance":
      return (
        <SettingsFieldSet legend="Performance">
          <NumberField label="RX/TX workers" value={draft.rxTxWorkers} onChange={(rxTxWorkers) => onDraft({ ...draft, rxTxWorkers })} />
          <NumberField label="Tunnel process workers" value={draft.tunnelProcessWorkers} onChange={(tunnelProcessWorkers) => onDraft({ ...draft, tunnelProcessWorkers })} />
          <NumberField label="TX channel size" value={draft.txChannelSize} onChange={(txChannelSize) => onDraft({ ...draft, txChannelSize })} />
          <NumberField label="RX channel size" value={draft.rxChannelSize} onChange={(rxChannelSize) => onDraft({ ...draft, rxChannelSize })} />
          <NumberField label="Max active streams" value={draft.maxActiveStreams} onChange={(maxActiveStreams) => onDraft({ ...draft, maxActiveStreams })} />
        </SettingsFieldSet>
      );
    case "reliability":
      return (
        <SettingsFieldSet legend="Reliability">
          <NumberField label="Tunnel packet timeout" value={draft.tunnelPacketTimeoutSeconds} step="0.1" onChange={(tunnelPacketTimeoutSeconds) => onDraft({ ...draft, tunnelPacketTimeoutSeconds })} />
          <NumberField label="Dispatcher idle poll interval" value={draft.dispatcherIdlePollIntervalSeconds} step="0.001" onChange={(dispatcherIdlePollIntervalSeconds) => onDraft({ ...draft, dispatcherIdlePollIntervalSeconds })} />
          <NumberField label="Stream queue capacity" value={draft.streamQueueInitialCapacity} onChange={(streamQueueInitialCapacity) => onDraft({ ...draft, streamQueueInitialCapacity })} />
          <NumberField label="Orphan queue capacity" value={draft.orphanQueueInitialCapacity} onChange={(orphanQueueInitialCapacity) => onDraft({ ...draft, orphanQueueInitialCapacity })} />
          <NumberField label="DNS fragment capacity" value={draft.dnsResponseFragmentStoreCapacity} onChange={(dnsResponseFragmentStoreCapacity) => onDraft({ ...draft, dnsResponseFragmentStoreCapacity })} />
          <NumberField label="Terminal stream retention" value={draft.clientTerminalStreamRetentionSeconds} step="0.1" onChange={(clientTerminalStreamRetentionSeconds) => onDraft({ ...draft, clientTerminalStreamRetentionSeconds })} />
          <NumberField label="Cancelled setup retention" value={draft.clientCancelledSetupRetentionSeconds} step="0.1" onChange={(clientCancelledSetupRetentionSeconds) => onDraft({ ...draft, clientCancelledSetupRetentionSeconds })} />
          <NumberField label="Retry base" value={draft.sessionInitRetryBaseSeconds} step="0.1" onChange={(sessionInitRetryBaseSeconds) => onDraft({ ...draft, sessionInitRetryBaseSeconds })} />
          <NumberField label="Retry step" value={draft.sessionInitRetryStepSeconds} step="0.1" onChange={(sessionInitRetryStepSeconds) => onDraft({ ...draft, sessionInitRetryStepSeconds })} />
          <NumberField label="Retry linear after" value={draft.sessionInitRetryLinearAfter} onChange={(sessionInitRetryLinearAfter) => onDraft({ ...draft, sessionInitRetryLinearAfter })} />
          <NumberField label="Retry max" value={draft.sessionInitRetryMaxSeconds} step="0.1" onChange={(sessionInitRetryMaxSeconds) => onDraft({ ...draft, sessionInitRetryMaxSeconds })} />
          <NumberField label="Busy retry interval" value={draft.sessionInitBusyRetryIntervalSeconds} step="0.1" onChange={(sessionInitBusyRetryIntervalSeconds) => onDraft({ ...draft, sessionInitBusyRetryIntervalSeconds })} />
          {normalizeImportType(draft.importType) === "masterdns" && (
            <NumberField label="Session init racing count" value={draft.sessionInitRacingCount} onChange={(sessionInitRacingCount) => onDraft({ ...draft, sessionInitRacingCount })} />
          )}
          {normalizeImportType(draft.importType) === "stormdns" && (
            <NumberField label="Ping watchdog" value={draft.pingWatchdogSeconds} onChange={(pingWatchdogSeconds) => onDraft({ ...draft, pingWatchdogSeconds })} />
          )}
        </SettingsFieldSet>
      );
  }
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

function ScannerPage({
  state,
  scanner,
  onState,
  onAppState,
  onError,
}: {
  state: AppState;
  scanner: ScannerState;
  onState: (state: ScannerState) => void;
  onAppState: (state: AppState) => void;
  onError: (message: string) => void;
}) {
  const running = scanner.status === "running";
  const [connectionProfileId, setConnectionProfileId] = useState(scanner.selectedConnectionProfileId || state.selectedConnectionProfileId);
  const [scanParallel, setScanParallel] = useState(scanner.scanParallel || 200);
  const [profileName, setProfileName] = useState("Scanned DNS Resolvers");
  const [statusText, setStatusText] = useState("");
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (scanner.selectedConnectionProfileId) {
      setConnectionProfileId(scanner.selectedConnectionProfileId);
    } else if (!connectionProfileId) {
      setConnectionProfileId(state.selectedConnectionProfileId);
    }
  }, [scanner.selectedConnectionProfileId, state.selectedConnectionProfileId]);

  useEffect(() => {
    if (scanner.scanParallel > 0) {
      setScanParallel(scanner.scanParallel);
    }
  }, [scanner.scanParallel]);

  useEffect(() => {
    if (!running) {
      return;
    }
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  const selectedConnection = state.connectionProfiles.find((profile) => profile.id === connectionProfileId) || state.connectionProfiles[0];
  const connectionReady = Boolean(selectedConnection?.domain.trim() && selectedConnection.encryptionKey.trim());
  const progress = scanner.total > 0 ? Math.round((scanner.completed / scanner.total) * 100) : 0;
  const elapsed = scanner.startedAt ? formatElapsed(scanner.startedAt, scanner.finishedAt || now) : "-";
  const canStart = !running && Boolean(scanner.inputFileName) && connectionReady;
  const validResolvers = scanner.validResolvers || [];

  async function chooseFile() {
    setStatusText("");
    try {
      onState(await backend.selectScannerInputFile());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function startScan() {
    setStatusText("");
    try {
      onState(await backend.startScannerScan({
        connectionProfileId,
        scanParallel,
      }));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function pauseOrResume() {
    try {
      onState(await backend.setScannerPaused(!scanner.paused));
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function cancelScan() {
    try {
      onState(await backend.cancelScannerScan());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function clearResults() {
    setStatusText("");
    try {
      onState(await backend.clearScannerResults());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function saveProfile() {
    try {
      const result = await backend.saveScannerResolverProfile(profileName);
      onAppState(result.state);
      setStatusText(`Saved ${result.imported} resolver${result.imported === 1 ? "" : "s"} as ${result.profile.name}.`);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function copyValidResolvers() {
    try {
      await navigator.clipboard?.writeText(validResolvers.join("\n"));
      setStatusText(`Copied ${validResolvers.length} resolver${validResolvers.length === 1 ? "" : "s"}.`);
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function applyUpgrade(action: "save" | "runtime") {
    try {
      const nextState = await backend.applyScannerConnectionUpgrade(action);
      onAppState(nextState);
      onState(await backend.getScannerState());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  async function keepCurrentUpgrade() {
    try {
      onState(await backend.dismissScannerConnectionUpgrade());
    } catch (err) {
      onError(messageFromError(err));
    }
  }

  return (
    <PageShell
      eyebrow="Scanner"
      title="DNS Scanner"
      actions={
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={running} onClick={chooseFile}>
            <Upload />
            File
          </Button>
          <Button variant="outline" disabled={!running} onClick={pauseOrResume}>
            {scanner.paused ? <Play /> : <Pause />}
            {scanner.paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" disabled={!running} onClick={cancelScan}>
            <Square />
            Cancel
          </Button>
          <Button variant="outline" disabled={running || (!scanner.inputFileName && scanner.status === "idle")} onClick={clearResults}>
            <Trash2 />
            Clear
          </Button>
          <Button disabled={!canStart} onClick={startScan}>
            <Search />
            Scan
          </Button>
        </div>
      }
    >
      <div className="grid gap-4 xl:grid-cols-[420px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Scan input</CardTitle>
            <CardDescription>{scanner.inputFileName || "Choose a file-backed resolver list."}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <FieldGroup>
              <Field>
                <FieldLabel>Connection profile</FieldLabel>
                <Select value={connectionProfileId} onValueChange={setConnectionProfileId} disabled={running}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {state.connectionProfiles.map((profile) => (
                      <SelectItem key={profile.id} value={profile.id}>
                        {profile.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FieldDescription>{selectedConnection?.domain || "Domain required"}</FieldDescription>
              </Field>
              <NumberField
                label="Scan parallel"
                value={scanParallel}
                min={1}
                max={1000}
                onChange={setScanParallel}
              />
            </FieldGroup>

            {!connectionReady && (
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>Connection profile incomplete</AlertTitle>
                <AlertDescription>Choose a profile with domain and encryption key.</AlertDescription>
              </Alert>
            )}

            <div className="grid gap-3 sm:grid-cols-2">
              <Metric label="Valid input" value={`${scanner.total}`} compact />
              <Metric label="Invalid skipped" value={`${scanner.invalid}`} compact />
              <Metric label="Duplicates" value={`${scanner.duplicates}`} compact />
              <Metric label="Elapsed" value={elapsed} compact />
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <StatusDot status={scannerStatusDot(scanner.status)} />
                {scannerStatusLabel(scanner.status, scanner.paused)}
              </CardTitle>
              <CardDescription>{scanner.message || (scanner.total ? `${scanner.completed} of ${scanner.total} resolvers complete` : "No scan running")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Progress value={progress} />
              <ScannerStatStrip
                stats={[
                  { label: "Completed", value: scanner.completed },
                  { label: "Total", value: scanner.total },
                  { label: "Valid", value: scanner.valid },
                  { label: "Rejected", value: scanner.rejected },
                  { label: "Parallel", value: scanner.scanParallel || scanParallel },
                ]}
              />
              {scanner.error && (
                <Alert variant="destructive">
                  <AlertCircle />
                  <AlertTitle>Scanner failed</AlertTitle>
                  <AlertDescription>{scanner.error}</AlertDescription>
                </Alert>
              )}
              {scanner.mode === "connection-upgrade" && scanner.restartAvailable && !scanner.autoRestart && (
                <div className="flex flex-wrap gap-2 rounded-lg border bg-background/70 p-3">
                  <Button type="button" size="sm" onClick={() => applyUpgrade("save")}>
                    <Save />
                    Save profile and restart
                  </Button>
                  <Button type="button" size="sm" variant="outline" onClick={() => applyUpgrade("runtime")}>
                    <RotateCcw />
                    Restart once
                  </Button>
                  <Button type="button" size="sm" variant="outline" onClick={keepCurrentUpgrade}>
                    <Square />
                    Keep current
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                  <CardTitle>Valid DNS resolvers</CardTitle>
                  <CardDescription>{validResolvers.length} resolver{validResolvers.length === 1 ? "" : "s"} ready to save</CardDescription>
                </div>
                <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap lg:justify-end">
                  <Button type="button" variant="outline" disabled={!validResolvers.length} onClick={copyValidResolvers}>
                    <Copy />
                    Copy
                  </Button>
                  <Button type="button" disabled={!validResolvers.length} onClick={saveProfile}>
                    <Save />
                    Save profile
                  </Button>
                </div>
              </div>
              {statusText && <p className="text-xs font-medium text-muted-foreground">{statusText}</p>}
            </CardHeader>
            <CardContent className="space-y-3">
              <TextField label="Profile name" value={profileName} onChange={setProfileName} />
              {validResolvers.length ? (
                <ScrollArea className="h-[min(32rem,calc(100svh-22rem))] min-h-72 rounded-lg border">
                  <div className="divide-y font-mono text-xs">
                    {validResolvers.slice(0, 1000).map((resolver, index) => (
                      <div key={`${resolver}-${index}`} className="px-3 py-2">
                        {resolver}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <Empty className="border">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <Search />
                    </EmptyMedia>
                    <EmptyTitle>No valid resolvers</EmptyTitle>
                    <EmptyDescription>Valid DNS resolvers appear here as the scan runs.</EmptyDescription>
                  </EmptyHeader>
                </Empty>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </PageShell>
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
                    "flex w-full min-w-0 items-center gap-3 px-3 py-2 text-left text-sm transition-colors hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-60",
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
                <div className="text-right">Actions</div>
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
  const title = titleOverride || (runtimeType === "v2ray" ? "V2Ray Diagnostics" : "MasterDNS Diagnostics");
  const description = descriptionOverride || (runtimeType === "v2ray"
    ? "Xray, V2Ray proxy, and health-check logs."
    : "MasterDNS/StormDNS runtime diagnostics.");
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
            <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input className="pl-8" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search logs" />
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

function ProfileWorkspace({
  title,
  items,
  selectedId,
  onSelect,
  onReorder,
  children,
}: {
  title: string;
  items: ProfileListItem[];
  selectedId: string;
  onSelect: (id: string) => void;
  onReorder?: (ids: string[]) => Promise<void> | void;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
      <Card className="min-h-0 lg:sticky lg:top-6 lg:max-h-[calc(100svh-3rem)]">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
          <CardDescription>Select an existing profile or create a new one.</CardDescription>
        </CardHeader>
        <CardContent className="min-h-0 flex-1 overflow-hidden">
          <ProfileList items={items} selectedId={selectedId} onSelect={onSelect} onReorder={onReorder} />
        </CardContent>
      </Card>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

type ProfileListItem = { id: string; title: string; detail: string; badges?: string[] };
type ProfileDropTarget = { id: string; position: "before" | "after" };

function ProfileList({
  items,
  selectedId,
  onSelect,
  onReorder,
  className,
}: {
  items: ProfileListItem[];
  selectedId: string;
  onSelect: (id: string) => void;
  onReorder?: (ids: string[]) => Promise<void> | void;
  className?: string;
}) {
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<ProfileDropTarget | null>(null);
  const canReorder = Boolean(onReorder && items.length > 1);

  function startDrag(event: DragEvent<HTMLButtonElement>, id: string) {
    if (!canReorder) {
      return;
    }
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", id);
    setDraggedId(id);
  }

  function finishDrag() {
    setDraggedId(null);
    setDropTarget(null);
  }

  function targetFromEvent(event: DragEvent<HTMLDivElement>, itemId: string): ProfileDropTarget | null {
    if (!canReorder || !draggedId || itemId === draggedId) {
      return null;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    return {
      id: itemId,
      position: event.clientY < rect.top + rect.height / 2 ? "before" : "after",
    };
  }

  function dragOverItem(event: DragEvent<HTMLDivElement>, itemId: string) {
    const target = targetFromEvent(event, itemId);
    if (!target) {
      if (itemId === draggedId) {
        setDropTarget(null);
      }
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    setDropTarget(target);
  }

  function dragOverEnd(event: DragEvent<HTMLDivElement>) {
    if (!canReorder || !draggedId) {
      return;
    }
    const last = items[items.length - 1];
    if (!last || last.id === draggedId) {
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    setDropTarget({ id: last.id, position: "after" });
  }

  async function dropOn(event: DragEvent<HTMLDivElement>, target: ProfileDropTarget | null = dropTarget) {
    event.preventDefault();
    if (!draggedId || !target || !onReorder) {
      finishDrag();
      return;
    }

    const nextIds = reorderedProfileIds(items, draggedId, target);
    finishDrag();
    if (!nextIds || idsAreEqual(nextIds, items.map((item) => item.id))) {
      return;
    }
    await onReorder(nextIds);
  }

  return (
    <ScrollArea className={cn("h-[min(32rem,calc(100svh-14rem))] min-h-0", className)}>
      <ItemGroup className="gap-2 pr-3">
        {items.map((item) => {
          const isDropBefore = dropTarget?.id === item.id && dropTarget.position === "before";
          const isDropAfter = dropTarget?.id === item.id && dropTarget.position === "after";
          return (
            <div
              key={item.id}
              role="listitem"
              onDragOver={(event) => dragOverItem(event, item.id)}
              onDrop={(event) => dropOn(event, targetFromEvent(event, item.id))}
            >
              {isDropBefore && <ProfileDropIndicator />}
              <Item
                variant={item.id === selectedId ? "muted" : "outline"}
                className={cn(item.id === selectedId && "border-foreground/20", draggedId === item.id && "opacity-50")}
              >
                {canReorder && (
                  <button
                    type="button"
                    draggable
                    aria-label={`Reorder ${item.title}`}
                    aria-grabbed={draggedId === item.id}
                    className="flex size-8 shrink-0 cursor-grab items-center justify-center rounded-md text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50 active:cursor-grabbing"
                    onDragStart={(event) => startDrag(event, item.id)}
                    onDragEnd={finishDrag}
                  >
                    <GripVertical />
                  </button>
                )}
                <button
                  type="button"
                  className="flex min-w-0 flex-1 rounded-sm text-left outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                  onClick={() => onSelect(item.id)}
                >
                  <ItemContent>
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <ItemTitle className="min-w-0 truncate">{item.title}</ItemTitle>
                      {item.badges?.map((badge) => (
                        <Badge key={badge} variant="secondary" className="shrink-0 px-1.5 py-0 text-[10px] leading-4">
                          {badge}
                        </Badge>
                      ))}
                    </div>
                    <ItemDescription>{item.detail}</ItemDescription>
                  </ItemContent>
                </button>
              </Item>
              {isDropAfter && <ProfileDropIndicator />}
            </div>
          );
        })}
        {canReorder && (
          <div
            className="h-3"
            onDragOver={dragOverEnd}
            onDrop={(event) => {
              const last = items[items.length - 1];
              void dropOn(event, last ? { id: last.id, position: "after" } : null);
            }}
          />
        )}
      </ItemGroup>
    </ScrollArea>
  );
}

function ProfileDropIndicator() {
  return <div className="my-1 h-0.5 rounded-full bg-foreground/70" />;
}

function reorderedProfileIds(items: ProfileListItem[], draggedId: string, target: ProfileDropTarget): string[] | null {
  if (draggedId === target.id) {
    return null;
  }
  const nextIds = items.filter((item) => item.id !== draggedId).map((item) => item.id);
  const targetIndex = nextIds.indexOf(target.id);
  if (targetIndex === -1) {
    return null;
  }
  nextIds.splice(target.position === "before" ? targetIndex : targetIndex + 1, 0, draggedId);
  return nextIds;
}

function idsAreEqual(left: string[], right: string[]) {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((id, index) => id === right[index]);
}

function EditorHeader({
  eyebrow,
  title,
  canDelete,
  onSave,
  onDelete,
}: {
  eyebrow: string;
  title: string;
  canDelete: boolean;
  onSave: () => void;
  onDelete: () => void;
}) {
  return (
    <CardHeader>
      <CardTitle>{title}</CardTitle>
      <CardDescription>{eyebrow}</CardDescription>
      <CardAction>
        <EditorActions canDelete={canDelete} onSave={onSave} onDelete={onDelete} />
      </CardAction>
    </CardHeader>
  );
}

function EditorActions({
  canDelete,
  canSave = true,
  onReset,
  onSave,
  onDelete,
}: {
  canDelete: boolean;
  canSave?: boolean;
  onReset?: () => void;
  onSave: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {onReset && (
        <Button type="button" variant="outline" onClick={onReset}>
          <RotateCcw />
          Reset defaults
        </Button>
      )}
      <Button type="button" disabled={!canSave} title={!canSave ? "Create a new profile to save changes" : undefined} onClick={onSave}>
        <Save />
        Save
      </Button>
      <Button type="button" variant="destructive" disabled={!canDelete} onClick={onDelete}>
        <Trash2 />
        Delete
      </Button>
    </div>
  );
}

function DashboardSelector({
  label,
  value,
  detail,
  items,
  disabled,
  onChange,
}: {
  label: string;
  value?: string;
  detail: string;
  items: Array<{ id: string; title: string; detail?: string; detailClassName?: string }>;
  disabled: boolean;
  onChange: (id: string) => void;
}) {
  const useNativeSelect = items.length > dashboardNativeSelectThreshold;
  return (
    <Field className="min-w-0 gap-1" data-disabled={disabled || undefined}>
      <div className="flex min-w-0 items-center justify-between gap-3">
        <FieldLabel className="text-xs font-medium">{label}</FieldLabel>
        <span className="min-w-0 truncate text-right text-xs text-muted-foreground">{detail}</span>
      </div>
      {useNativeSelect ? (
        <select
          value={value || ""}
          disabled={disabled}
          className="h-8 w-full rounded-md border border-input bg-background px-3 text-sm outline-none transition-colors disabled:cursor-not-allowed disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-ring"
          onChange={(event) => onChange(event.target.value)}
        >
          {items.map((item) => (
            <option key={item.id} value={item.id}>
              {item.detail ? `${item.title} - ${item.detail}` : item.title}
            </option>
          ))}
        </select>
      ) : (
        <Select value={value || ""} disabled={disabled} onValueChange={(id) => onChange(String(id))}>
          <SelectTrigger className="h-8 w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {items.map((item) => (
              <SelectItem key={item.id} value={item.id}>
                <span className="flex min-w-0 flex-1 items-center justify-between gap-3">
                  <span className="min-w-0 truncate">{item.title}</span>
                  {item.detail && (
                    <span className={cn("shrink-0 text-xs text-muted-foreground", item.detailClassName)}>
                      {item.detail}
                    </span>
                  )}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </Field>
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

function ScannerStatStrip({ stats, compact }: { stats: Array<{ label: string; value: number | string }>; compact?: boolean }) {
  return (
    <dl className={cn("flex flex-wrap items-center gap-y-1.5", compact ? "mt-2 gap-x-3 text-xs" : "gap-x-5 gap-y-2 text-sm")}>
      {stats.map((stat) => (
        <div key={stat.label} className="inline-flex min-w-0 items-baseline gap-1.5">
          <dt className="text-muted-foreground">{stat.label}</dt>
          <dd className="font-semibold tabular-nums text-foreground">{stat.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function ResolverStatusPill({
  tone,
  label,
  value,
  onClick,
}: {
  tone: "active" | "valid" | "standby" | "rejected";
  label: string;
  value: number;
  onClick?: () => void;
}) {
  const className = cn(
    "inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-sm font-semibold transition-colors",
    tone === "active" && "bg-emerald-50 text-emerald-900",
    tone === "valid" && "bg-sky-50 text-sky-900",
    tone === "standby" && "bg-amber-50 text-amber-900",
    tone === "rejected" && "bg-red-50 text-red-900",
    onClick && "cursor-pointer hover:brightness-95 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
  );
  const dot = (
    <span
      className={cn(
        "size-2 rounded-full",
        tone === "active" && "bg-emerald-700",
        tone === "valid" && "bg-sky-700",
        tone === "standby" && "bg-amber-800",
        tone === "rejected" && "bg-red-800"
      )}
    />
  );
  const content = (
    <>
      {dot}
      <span>{value} {label}</span>
    </>
  );

  if (onClick) {
    return (
      <button type="button" className={className} onClick={onClick}>
        {content}
      </button>
    );
  }

  return (
    <div className={className}>
      {content}
    </div>
  );
}

function ResolverPreview({
  resolvers,
  totalCount,
  onMoreClick,
}: {
  resolvers: string[];
  totalCount?: number;
  onMoreClick?: () => void;
}) {
  if (!resolvers.length) {
    return (
      <Empty className="border">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <Globe2 />
          </EmptyMedia>
          <EmptyTitle>No validated resolvers</EmptyTitle>
          <EmptyDescription>Add resolver entries before connecting.</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }
  const visibleResolvers = resolvers.slice(0, 8);
  const hiddenResolverCount = Math.max((totalCount || resolvers.length) - visibleResolvers.length, 0);

  return (
    <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
      {visibleResolvers.map((resolver, index) => (
        <code
          key={`${resolver}-${index}`}
          className="flex min-w-0 items-center gap-2 rounded-lg bg-muted/35 px-3 py-2 font-mono text-sm text-foreground"
        >
          <span className="size-1.5 shrink-0 rounded-full bg-muted-foreground/45" />
          <span className="min-w-0 truncate">{resolver}</span>
        </code>
      ))}
      {hiddenResolverCount > 0 && (
        <button
          type="button"
          className="flex items-center rounded-lg bg-muted/35 px-3 py-2 text-left text-sm font-medium text-muted-foreground transition-colors hover:bg-muted/55 hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
          onClick={onMoreClick}
          disabled={!onMoreClick}
        >
          +{hiddenResolverCount} more
        </button>
      )}
    </div>
  );
}

function resolverDialogDetails(kind: "active" | "valid", resolvers: string[], details: ResolverRuntimeDetail[]): ResolverRuntimeDetail[] {
  const resolverSet = new Set(resolvers);
  const filtered = details.filter((detail) => {
    if (!resolverSet.has(detail.resolver)) {
      return false;
    }
    return kind === "active" ? detail.active : detail.valid;
  });
  if (filtered.length) {
    return filtered;
  }
  return resolvers.map((resolver) => ({
    resolver,
    domain: "",
    status: kind === "active" ? "active" : "valid",
    active: kind === "active",
    valid: true,
    uploadMtu: 0,
    downloadMtu: 0,
    uploadMtuChars: 0,
    lastEvent: "",
    cause: "",
  }));
}

function ResolverListDialog({
  open,
  title,
  description,
  copyLabel,
  resolvers,
  resolverDetails,
  copyStatus,
  onCopy,
  onOpenChange,
}: {
  open: boolean;
  title: string;
  description: string;
  copyLabel: string;
  resolvers: string[];
  resolverDetails: ResolverRuntimeDetail[];
  copyStatus: string;
  onCopy: () => void;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100svh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] overflow-hidden sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="min-h-0 overflow-auto rounded-lg border">
          <table className="w-full min-w-[56rem] border-collapse text-left text-sm">
            <thead className="sticky top-0 bg-muted text-xs font-semibold text-muted-foreground">
              <tr>
                <th className="px-3 py-2">Resolver</th>
                <th className="px-3 py-2">Domain</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">Upload MTU</th>
                <th className="px-3 py-2 text-right">Download MTU</th>
                <th className="px-3 py-2 text-right">Upload chars</th>
                <th className="px-3 py-2">Last event</th>
                <th className="px-3 py-2">Cause</th>
              </tr>
            </thead>
            <tbody>
              {resolverDetails.map((detail, index) => (
                <tr key={`${detail.resolver}-${detail.domain}-${index}`} className="border-t">
                  <td className="max-w-56 px-3 py-2 font-mono text-xs">
                    <span className="block truncate">{detail.resolver || "-"}</span>
                  </td>
                  <td className="max-w-56 px-3 py-2 font-mono text-xs">
                    <span className="block truncate">{detail.domain || "-"}</span>
                  </td>
                  <td className="px-3 py-2">
                    <ResolverDetailStatus detail={detail} />
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-xs">{formatResolverDetailNumber(detail.uploadMtu)}</td>
                  <td className="px-3 py-2 text-right font-mono text-xs">{formatResolverDetailNumber(detail.downloadMtu)}</td>
                  <td className="px-3 py-2 text-right font-mono text-xs">{formatResolverDetailNumber(detail.uploadMtuChars)}</td>
                  <td className="px-3 py-2 text-xs">{detail.lastEvent || "-"}</td>
                  <td className="max-w-60 px-3 py-2 text-xs text-muted-foreground">
                    <span className="block truncate">{detail.cause || "-"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <DialogFooter>
          {copyStatus && <span className="self-center text-xs font-medium text-muted-foreground">{copyStatus}</span>}
          <Button type="button" onClick={onCopy} disabled={!resolvers.length}>
            <Copy />
            {copyLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ResolverDetailStatus({ detail }: { detail: ResolverRuntimeDetail }) {
  const status = detail.active ? "active" : detail.valid ? "valid" : detail.status || "inactive";
  const tone = detail.active
    ? "bg-emerald-50 text-emerald-900"
    : detail.valid
      ? "bg-sky-50 text-sky-900"
      : "bg-muted text-muted-foreground";
  return (
    <span className={cn("inline-flex rounded-full px-2 py-0.5 text-xs font-semibold", tone)}>
      {status}
    </span>
  );
}

function formatResolverDetailNumber(value: number): string {
  return value > 0 ? String(value) : "-";
}

function ResolverFilePreview({
  page,
  fallback,
  onPrevious,
  onNext,
}: {
  page: ResolverPreviewPage | null;
  fallback: string[];
  onPrevious: () => void;
  onNext: () => void;
}) {
  const resolvers = page?.resolvers?.length ? page.resolvers : fallback;
  const offset = page?.offset || 0;
  const total = page?.total || fallback.length;
  const hasPrevious = offset > 0;
  const hasNext = Boolean(page?.hasMore);
  const textareaValue = resolvers.join("\n");

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">
          {total ? `${offset + 1}-${Math.min(offset + resolvers.length, total)} of ${total}` : "No resolvers"}
        </p>
        <div className="flex items-center gap-1">
          <Button type="button" variant="outline" size="icon-sm" disabled={!hasPrevious} onClick={onPrevious} aria-label="Previous resolvers">
            <ChevronLeft />
          </Button>
          <Button type="button" variant="outline" size="icon-sm" disabled={!hasNext} onClick={onNext} aria-label="Next resolvers">
            <ChevronRight />
          </Button>
        </div>
      </div>
      <Textarea
        readOnly
        aria-label="Resolver file preview"
        value={textareaValue}
        className="h-[min(28rem,calc(100svh-24rem))] min-h-72 max-h-[28rem] resize-none overflow-y-auto font-mono text-sm leading-relaxed [field-sizing:fixed]"
      />
    </div>
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

function SecretField(props: {
  label: string;
  value: string;
  error?: string;
  revealable?: boolean;
  onChange: (value: string) => void;
}) {
  const [visible, setVisible] = useState(false);
  const revealLabel = visible ? `Hide ${props.label.toLowerCase()}` : `Show ${props.label.toLowerCase()}`;

  return (
    <Field data-invalid={Boolean(props.error)}>
      <FieldLabel>{props.label}</FieldLabel>
      <div className="relative">
        <Input
          type={props.revealable && visible ? "text" : "password"}
          value={props.value}
          aria-invalid={Boolean(props.error)}
          className={props.revealable ? "pr-9" : undefined}
          onChange={(event) => props.onChange(event.target.value)}
        />
        {props.revealable && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                className="absolute right-1 top-1/2 size-6 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label={revealLabel}
                aria-pressed={visible}
                onClick={() => setVisible((current) => !current)}
              >
                {visible ? <EyeOff /> : <Eye />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>{revealLabel}</TooltipContent>
          </Tooltip>
        )}
      </div>
      <FieldError>{props.error}</FieldError>
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
        (status === "connecting" || status === "parallel-testing") && "bg-emerald-300 ring-emerald-50",
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
    case "parallel-testing":
      return "border-[var(--connecting-card-border)] bg-[var(--connecting-card-bg)]";
    case "failed":
      return "border-red-100 bg-red-50";
    default:
      return "bg-card";
  }
}

function statusButtonTone(status: string): string {
  switch (status) {
    case "connected":
      return "border-emerald-200 bg-emerald-100 text-emerald-950 hover:bg-emerald-200";
    case "connecting":
      return "border-red-200 bg-red-50 text-red-900 hover:bg-red-100";
    case "failed":
      return "border-red-100 bg-red-50 text-red-900 hover:bg-red-100";
    default:
      return "border-border bg-background text-foreground hover:bg-muted";
  }
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "failed") {
    return "destructive";
  }
  if (status === "connected") {
    return "default";
  }
  if (status === "connecting" || status === "parallel-testing") {
    return "outline";
  }
  return "secondary";
}

function compressionOptions(): Array<[string, string]> {
  return [
    ["0", "Off"],
    ["1", "Zstandard"],
    ["2", "LZ4"],
    ["3", "Zlib"],
  ];
}

function encryptionMethodLabel(method: number): string {
  switch (method) {
    case 0:
      return "None";
    case 2:
      return "ChaCha20";
    case 3:
      return "AES-128-GCM";
    case 4:
      return "AES-192-GCM";
    case 5:
      return "AES-256-GCM";
    case 1:
    default:
      return "XOR";
  }
}

function sectionLabel(section: SettingsSection): string {
  return settingsSections.find((item) => item.id === section)?.label || "Settings";
}

function statusLabel(status: string): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "connecting":
      return "Connecting";
    case "parallel-testing":
      return "Parallel Testing";
    case "failed":
      return "Failed";
    default:
      return "Disconnected";
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

function progressSummary(progress: RuntimeStatus["progress"]): string {
  if (progress.phase === "session") {
    return progress.completed > 0 ? `Session init retrying (${progress.completed})` : "Initializing session";
  }
  if (progress.total > 0) {
    return `${progress.completed || 0} of ${progress.total} checks complete`;
  }
  return "Preparing runtime checks";
}

function getMTUResolverFailureWarning(runtime: RuntimeStatus): { title: string; description: string } | null {
  if (runtime.status !== "failed") {
    return null;
  }

  const progress = runtime.progress;
  const resolverState = runtime.resolverState;
  const total = Math.max(resolverState.totalCount || 0, progress.total || 0);
  const valid = Math.max(
    resolverRuntimeCount(resolverState.activeResolvers || [], resolverState.activeCount),
    resolverRuntimeCount(resolverState.validResolvers || [], resolverState.validCount),
    progress.valid || 0
  );
  const rejected = Math.max(resolverState.rejectedCount || 0, progress.rejected || 0);
  const completed = Math.max(progress.completed || 0, valid + rejected);
  const pending = resolverState.pendingCount || 0;
  const mtuChecksRan = progress.phase === "mtu" || total > 0 || completed > 0 || rejected > 0;

  if (!mtuChecksRan || valid > 0 || rejected <= 0) {
    return null;
  }

  const allKnownResolversRejected = total > 0 && completed >= total && rejected >= total && pending <= 0;
  const completedChecksAllRejected = total <= 0 && completed > 0 && rejected >= completed;
  if (!allKnownResolversRejected && !completedChecksAllRejected) {
    return null;
  }

  const totalLabel = total > 0 ? total : completed;
  return {
    title: "Resolvers did not pass MTU checks",
    description: `0 of ${totalLabel} MTU checks passed; ${rejected} rejected. No resolvers passed validation, so the connection could not start.`,
  };
}

function formatSpeed(value: number): string {
  return `${formatBytes(value)}/s`;
}

function formatCount(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString() : "0";
}

function parallelCandidateSpeedLabel(candidate: { downloadBytesPerSecond: number; speedTestError: string }): string {
  if (candidate.downloadBytesPerSecond > 0) {
    return `${formatSpeed(candidate.downloadBytesPerSecond)} download`;
  }
  return candidate.speedTestError ? "speed unavailable" : "speed pending";
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

function formatDuration(value: number): string {
  if (!value || value < 1000) {
    return `${Math.max(0, Math.round(value || 0))} ms`;
  }
  return `${(value / 1000).toFixed(value >= 10000 ? 0 : 1)} s`;
}

function parallelTestStatusLabel(status: string): string {
  switch (status) {
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "cancelled":
      return "Cancelled";
    default:
      return "Idle";
  }
}

function parallelTestStatusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "completed":
      return "default";
    case "failed":
      return "destructive";
    case "running":
      return "outline";
    default:
      return "secondary";
  }
}

function formatParallelFinishedAt(value: number): string {
  if (!value) {
    return "";
  }
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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

function parallelPhaseLabel(phase: string): string {
  switch (phase) {
    case "resolvers":
      return "Finding resolvers";
    case "candidates":
      return "Testing configs";
    case "connecting":
      return "Connecting winner";
    default:
      return "Parallel test";
  }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function scannerStatusDot(status: string): string {
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

function scannerStatusLabel(status: string, paused: boolean): string {
  if (status === "running" && paused) {
    return "Scanner paused";
  }
  switch (status) {
    case "running":
      return "Scanner running";
    case "completed":
      return "Scan complete";
    case "cancelled":
      return "Scan cancelled";
    case "failed":
      return "Scan failed";
    default:
      return "Scanner idle";
  }
}

function formatElapsed(startedAt: number, endedAt: number): string {
  const seconds = Math.max(0, Math.floor((endedAt - startedAt) / 1000));
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes <= 0) {
    return `${remainder}s`;
  }
  return `${minutes}m ${remainder.toString().padStart(2, "0")}s`;
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

function isExportableConnection(profile: ConnectionProfile): boolean {
  return Boolean(profile.domain.trim() && profile.encryptionKey.trim());
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
