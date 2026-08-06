export type RuntimeStatusName = "disconnected" | "connecting" | "connected" | "stopping" | "failed";
export type RuntimeType = "" | "masterdns" | "v2ray";

export interface ConnectionProfile {
  id: string;
  name: string;
  importType: ImportType;
  domain: string;
  encryptionKey: string;
  encryptionMethod: number;
  resolverProfileId: string;
}

export type ImportType = "masterdns" | "stormdns";

export interface ResolverProfile {
  id: string;
  name: string;
  resolverText: string;
  resolverSource?: string;
  resolverFile?: string;
  resolverCount?: number;
  resolverPreview?: string[] | null;
  resolverInvalidCount?: number;
}

export type V2RayProtocol = "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria2" | "wireguard" | "socks" | "http";

export interface V2RayProfile {
  id: string;
  name: string;
  subscriptionId: string;
  protocol: V2RayProtocol;
  server: string;
  serverPort: number;
  uuid: string;
  password: string;
  alterId: number;
  security: string;
  flow: string;
  packetEncoding: string;
  network: string;
  tls: boolean;
  sni: string;
  alpn: string;
  allowInsecure: boolean;
  utlsFingerprint: string;
  echConfigList: string;
  reality: boolean;
  realityPublicKey: string;
  realityShortId: string;
  transportPath: string;
  transportHost: string;
  serviceName: string;
  xhttpMode: string;
  xhttpExtra: string;
  webSocketEarlyData: number;
  webSocketEarlyDataHeader: string;
  username: string;
  shadowsocksMethod: string;
  uot: boolean;
  uotVersion: number;
  hysteriaAuth: string;
  hysteriaUdpIdleTimeout: number;
  hysteriaMasquerade: string;
  httpHeaders: string;
  wireGuardSecretKey: string;
  wireGuardLocalAddresses: string;
  wireGuardPeerPublicKey: string;
  wireGuardPreSharedKey: string;
  wireGuardAllowedIps: string;
  wireGuardKeepAlive: number;
  wireGuardMtu: number;
  wireGuardReserved: string;
  wireGuardNoKernelTun: boolean;
  wireGuardDomainStrategy: string;
  outboundSettings: string;
  streamSettings: string;
}

export interface V2RaySettingsProfile {
  id: string;
  name: string;
  listenIp: string;
  allowLan: boolean;
  listenPort: number;
  inboundType: string;
  setSystemProxy: boolean;
  tunEnabled: boolean;
  tunMtu: number;
  tunIpv6: boolean;
  tunInterfaceName: string;
  iranRoutingEnabled: boolean;
  logLevel: string;
}

export interface V2RaySubscription {
  id: string;
  name: string;
  url: string;
  lastUpdatedAt: string;
  lastError: string;
  importedCount: number;
}

export interface V2RayPingResult {
  profileId: string;
  endpoint: string;
  ok: boolean;
  latencyMs: number;
  message: string;
  downloadBytesPerSecond: number;
  speedTestBytes: number;
  speedTestDurationMs: number;
  speedOk: boolean;
  realDelayMs: number;
  delayOk: boolean;
  speedMessage: string;
  delayMessage: string;
}

export interface ConnectionTestResolver {
  endpoint: string;
  uploadMtu: number;
  downloadMtu: number;
  uploadMtuChars: number;
}

export interface ConnectionTestResult {
  profileId: string;
  ok: boolean;
  latencyMs: number;
  message: string;
  resolver: string;
  resolvers: ConnectionTestResolver[];
}

export interface V2RayDuplicateRemovalResult {
  state: AppState;
  removed: number;
}

export interface V2RayWhiteIPImportResult {
  state: AppState;
  imported: number;
  whiteIpCount: number;
  sourceProfileCount: number;
}

export interface V2RayWhiteIPGenerateResult {
  configText: string;
  generated: number;
  whiteIpCount: number;
  sourceProfileCount: number;
}

export interface SettingsProfile {
  id: string;
  name: string;
  importType: ImportType;
  listenIp: string;
  listenPort: number;
  socks5Authentication: boolean;
  socksUsername: string;
  socksPassword: string;
  singBoxEnabled: boolean;
  singBoxInboundType: string;
  singBoxSetSystemProxy: boolean;
  stormDnsListenIp: string;
  stormDnsListenPort: number;
  localDnsEnabled: boolean;
  localDnsPort: number;
  balancingStrategy: number;
  uploadDuplication: number;
  downloadDuplication: number;
  uploadCompression: number;
  downloadCompression: number;
  baseEncodeData: boolean;
  minUploadMtu: number;
  minDownloadMtu: number;
  maxUploadMtu: number;
  maxDownloadMtu: number;
  mtuTestRetriesResolvers: number;
  mtuTestTimeoutResolvers: number;
  mtuTestParallelismResolvers: number;
  mtuStartupLossVerifyEnabled: boolean;
  mtuStartupLossVerifySamples: number;
  mtuStartupLossVerifyMaxLossPercent: number;
  mtuStartupLossVerifyCandidates: number;
  mtuRecheckEnabled: boolean;
  mtuRecheckIntervalMinutes: number;
  mtuTestRetriesLogs: number;
  mtuTestTimeoutLogs: number;
  mtuTestParallelismLogs: number;
  connectionStartupMode: string;
  autoRemoveLowMtuServers: boolean;
  saveMtuServersToFile: boolean;
  mtuServersFileName: string;
  mtuServersFileFormat: string;
  mtuUsingSectionSeparatorText: string;
  mtuRemovedServerLogFormat: string;
  mtuAddedServerLogFormat: string;
  mtuReactiveAddedServerLogFormat: string;
  sessionInitRacingCount: number;
  rxTxWorkers: number;
  tunnelProcessWorkers: number;
  tunnelPacketTimeoutSeconds: number;
  dispatcherIdlePollIntervalSeconds: number;
  txChannelSize: number;
  rxChannelSize: number;
  resolverUdpConnectionPoolSize: number;
  streamQueueInitialCapacity: number;
  orphanQueueInitialCapacity: number;
  dnsResponseFragmentStoreCapacity: number;
  maxActiveStreams: number;
  localHandshakeTimeoutSeconds: number;
  socksUdpAssociateReadTimeoutSeconds: number;
  clientTerminalStreamRetentionSeconds: number;
  clientCancelledSetupRetentionSeconds: number;
  sessionInitRetryBaseSeconds: number;
  sessionInitRetryStepSeconds: number;
  sessionInitRetryLinearAfter: number;
  sessionInitRetryMaxSeconds: number;
  sessionInitBusyRetryIntervalSeconds: number;
  startupMode: string;
  pingWatchdogSeconds: number;
  logLevel: string;
}

export interface ConnectionProgress {
  phase: string;
  percent: number;
  completed: number;
  total: number;
  valid: number;
  rejected: number;
}

export interface ResolverRuntimeState {
  activeResolvers: string[] | null;
  standbyResolvers: string[] | null;
  validResolvers: string[] | null;
  resolverDetails: ResolverRuntimeDetail[] | null;
  totalCount: number;
  activeCount: number;
  standbyCount: number;
  validCount: number;
  rejectedCount: number;
  pendingCount: number;
  activeComplete: boolean;
  standbyComplete: boolean;
  validComplete: boolean;
}

export interface ResolverRuntimeDetail {
  resolver: string;
  domain: string;
  status: string;
  active: boolean;
  valid: boolean;
  uploadMtu: number;
  downloadMtu: number;
  uploadMtuChars: number;
  lastEvent: string;
  cause: string;
}

export interface TrafficStats {
  downloadBytes: number;
  uploadBytes: number;
  downloadSpeedBytesPerSecond: number;
  uploadSpeedBytesPerSecond: number;
  totalDataUsageBytes: number;
}

export interface CloudflarePingResult {
  ok: boolean;
  target: string;
  proxy: string;
  latencyMs: number;
  message: string;
}

export interface ProxyCountryLookupResult {
  ok: boolean;
  ip: string;
  countryCode: string;
  proxy: string;
  message: string;
}

export interface RuntimeStatus {
  status: RuntimeStatusName;
  engine: string;
  runtimeType: RuntimeType;
  message: string;
  activeConnectionId: string;
  listenIp: string;
  listenPort: number;
  proxyProtocol: "socks" | "http" | "";
  localProxyIp: string;
  publicProxyIp: string;
  frontingIp: string;
  // Whether the machine has been pointed at the local proxy.
  systemProxy: boolean;
  // The node carrying traffic, and where its own name says it is.
  nodeName: string;
  nodeCountryCode: string;
  // The address the internet sees traffic coming from. Not publicProxyIp,
  // which is where this machine's own proxy can be reached on the LAN.
  exitIp: string;
  // Where traffic is measured to actually leave from. It can disagree with
  // nodeCountryCode, and when it does this one is the true one.
  exitCountryCode: string;
  // Whether the measurement has been attempted, so one that found nothing can
  // be told from one still running.
  exitChecked: boolean;
  resolverMtuScanPaused: boolean;
  autoProfilePresetId: string;
  autoProfileName: string;
  progress: ConnectionProgress;
  resolverState: ResolverRuntimeState;
  stats: TrafficStats;
  trafficMonitorMessage: string;
  logs: string[];
  masterDnsLogs: string[];
  v2rayLogs: string[];
}

export interface RuntimeLogEntry {
  runtimeType: RuntimeType;
  line: string;
}

export interface FirewallStatus {
  enabled: boolean;
  supported: boolean;
  name: string;
  message: string;
}

export interface AppState {
  selectedConnectionProfileId: string;
  selectedResolverProfileId: string;
  selectedSettingsProfileId: string;
  selectedV2RayProfileId: string;
  selectedV2RaySettingsId: string;
  // The subscription the VPN connects through; the built-in catalogue by default.
  selectedSubscriptionId: string;
  theme: string;
  connectionProfiles: ConnectionProfile[];
  resolverProfiles: ResolverProfile[];
  settingsProfiles: SettingsProfile[];
  v2rayProfiles: V2RayProfile[];
  v2raySubscriptions: V2RaySubscription[];
  v2raySettingsProfiles: V2RaySettingsProfile[];
  whiteDNSVPNFrontingIps: string[];
  whiteVpn: WhiteVPNSettings;
  runtime: RuntimeStatus;
}

export interface ConnectionImportResult {
  state: AppState;
  imported: number;
}

export interface V2RayImportResult {
  state: AppState;
  imported: number;
}

export interface V2RaySubscriptionRefreshResult {
  state: AppState;
  subscription: V2RaySubscription;
  ok: boolean;
  message: string;
  imported: number;
  removed: number;
}

export interface ValidatorResolverProfileInput {
  endpoint: string;
  host: string;
  port: number;
}

export interface ValidatorResolverProfileRequest {
  results: ValidatorResolverProfileInput[];
}

export interface ResolverImportResult {
  state: AppState;
  profile: ResolverProfile;
  imported: number;
  skipped: number;
}

export interface ResolverPreviewPage {
  resolvers: string[];
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
}

export interface ResolverTextValidation {
  normalizedResolvers: string[];
  invalidEntries: string[];
  normalizedText: string;
  isValid: boolean;
}

export type ScannerStatus = "idle" | "running" | "cancelled" | "completed" | "failed";
export type ValidatorStatus = ScannerStatus;
export type ParallelTestStatus = "idle" | "running" | "cancelled" | "completed" | "failed";

export interface ValidatorEndpointInput {
  host: string;
  port: number;
  sni?: string;
}

export interface ValidatorOptions {
  retries: number;
  timeoutMillis: number;
  workerCount: number;
  adaptiveLimit?: number;
  httpPaths?: string[];
  dnsQuestion?: string;
  enableUdp: boolean;
  enableQuic: boolean;
  enableDns: boolean;
  enableWebSocket: boolean;
  allowInsecureCert: boolean;
}

export interface ValidatorRequest {
  mode: string;
  endpoints: ValidatorEndpointInput[];
  options: ValidatorOptions;
}

export interface ValidatorRangeOption {
  range: string;
  hostCount: number;
}

export interface ValidatorRangeImportResult {
  ranges: ValidatorRangeOption[];
  invalid: string[];
  invalidCount: number;
  duplicateCount: number;
  totalCount: number;
}

export interface ValidatorRangeRequest {
  mode: string;
  ranges: string[];
  port?: number;
  ports?: number[];
  sni?: string;
  options: ValidatorOptions;
}

export interface ScannerStartRequest {
  connectionProfileId: string;
  scanParallel: number;
}

export interface ScannerState {
  status: ScannerStatus;
  mode: string;
  paused: boolean;
  phase: string;
  message: string;
  selectedConnectionProfileId: string;
  inputFileName: string;
  scanParallel: number;
  bootstrapResolverCount: number;
  restartAvailable: boolean;
  autoRestart: boolean;
  scannedResolverCount: number;
  total: number;
  completed: number;
  valid: number;
  rejected: number;
  invalid: number;
  duplicates: number;
  validResolvers: string[];
  error: string;
  startedAt: number;
  finishedAt: number;
}

export interface ValidatorState {
  status: ValidatorStatus;
  paused: boolean;
  mode: string;
  total: number;
  completed: number;
  retained: number;
  ready: number;
  bestScore: number;
  gradeAPlus: number;
  gradeA: number;
  gradeB: number;
  gradeC: number;
  gradeF: number;
  ports?: number[];
  results: ValidatorResult[];
  resultsFileName?: string;
  resultsFilePath?: string;
  resultsFileRows: number;
  resultsFilePart: number;
  resultsFileCount: number;
  requestedWorkers: number;
  effectiveWorkers: number;
  workerCeiling: number;
  pressureEvents: number;
  error: string;
  startedAt: number;
  finishedAt: number;
  options: ValidatorOptions;
  appendResults?: boolean;
}

export interface ValidatorResult {
  endpoint: string;
  host: string;
  port: number;
  tcp: boolean;
  tls: boolean;
  http: boolean;
  webSocket: boolean;
  udp: boolean;
  quic: boolean;
  dns: boolean;
  rttMs: number;
  jitterMs: number;
  packetLoss: number;
  stability: number;
  score: number;
  grade: string;
  classification: string;
  confidence: number;
  falsePositive: boolean;
  reasons: string[];
  errors?: string[];
  rawJson?: string;
}

export interface ValidatorResultFile {
  name: string;
  runName?: string;
  part: number;
  path?: string;
  sizeBytes: number;
  rows: number;
  status: string;
  mode: string;
  total: number;
  completed: number;
  retained: number;
  ready: number;
  bestScore: number;
  startedAt: number;
  finishedAt: number;
  modifiedAt: number;
  resultsFileName?: string;
}

export interface ParallelTestCandidateResult {
  id: string;
  name: string;
  status: string;
  stability: number;
  rttMs: number;
  score: number;
  startDurationMs: number;
  downloadBytesPerSecond: number;
  speedTestBytes: number;
  speedTestDurationMs: number;
  speedTestError: string;
  error: string;
}

export interface ParallelTestPresetOption {
  id: string;
  name: string;
  category: string;
  saved: boolean;
  settings: SettingsProfile;
}

export interface ParallelTestState {
  status: ParallelTestStatus;
  phase: string;
  message: string;
  total: number;
  completed: number;
  running: number;
  resolverTarget: number;
  resolvers: string[];
  candidates: ParallelTestCandidateResult[];
  winnerPresetId: string;
  winnerPresetName: string;
  error: string;
  startedAt: number;
  finishedAt: number;
}

export type LegacyImportOffer = {
  available: boolean;
  profiles: number;
  subscriptions: number;
  frontingIps: number;
  sourcePath: string;
};

export type DNSPrivacyMode = "automatic" | "doh" | "dot";
export type SplitTunnelMode = "off" | "bypass_selected" | "vpn_only_selected";

export type AmneziaNoiseSettings = {
  enabled: boolean;
  count: number;
  minSize: number;
  maxSize: number;
};

export type DNSPrivacySettings = {
  mode: DNSPrivacyMode;
  dohUrl: string;
  dotEndpoint: string;
};

export type SplitTunnelSettings = {
  mode: SplitTunnelMode;
  processes: string[];
};

export type KillSwitchSettings = {
  enabled: boolean;
};

// The dashboard's node choice. An empty node means Automatic, and empty types
// means every protocol.
export type ConnectionSelection = {
  node: string;
  types: string[];
  delaySort: boolean;
};

// One node of the catalogue. `name` is its identity — what the engine selects
// by — and `label` is the same name with the flag and channel marker removed.
export type WhiteVPNNode = {
  name: string;
  label: string;
  type: string;
  countryCode: string;
  server: string;
  port: number;
  transport: string;
  tls: boolean;
  // The share link this node arrived as, which is what sharing hands back.
  link: string;
  // The stored config this node was made from, set only for configs added by
  // hand. A node from the catalogue or a subscription has none — it is a
  // reading of what the provider is serving and comes back unchanged at the
  // next refresh — which is how this page knows not to offer edit or delete
  // for it.
  profileId: string;
  // Measurements, each in one of three states rather than two: never run, run
  // and failed, run and measured. A node that could not be reached must not
  // look like one nobody has tested.
  // Each carries why it failed as well as that it did: "failed" on its own
  // tells someone to avoid a node without telling them why.
  reachTested: boolean;
  reachOk: boolean;
  reachMs: number;
  reachError: string;
  delayTested: boolean;
  delayOk: boolean;
  delayMs: number;
  delayError: string;
  speedTested: boolean;
  speedOk: boolean;
  speedBytesPerSecond: number;
  speedError: string;
};

// One run of the node tests: which nodes, which tests, and the numbers the user
// is allowed to change. Bounds live in internal/model; anything outside them is
// replaced with the default rather than clamped.
export type NodeTestRequest = {
  // Which subscription the names belong to; empty means the selected one.
  subscriptionId?: string;
  nodes: string[];
  reachability: boolean;
  delay: boolean;
  speed: boolean;
  reachabilityTimeoutMs: number;
  reachabilityWorkers: number;
  delayTimeoutMs: number;
  delayWorkers: number;
  delayUrl: string;
  speedBudgetMs: number;
  speedUrl: string;
};

export type WhiteVPNNodeList = {
  nodes: WhiteVPNNode[];
  updatedAt: string;
};

// Mirrors model.WhiteVPNSettings. Every field here is a setting WhiteVPN for
// Android exposes, so that someone moving from the phone finds the same options.
export type WhiteVPNSettings = {
  countryCode: string;
  connection: ConnectionSelection;
  splitTunnel: SplitTunnelSettings;
  tlsIntegrityEnabled: boolean;
  amneziaNoise: AmneziaNoiseSettings;
  frontingIps: string[];
  dnsPrivacy: DNSPrivacySettings;
  killSwitch: KillSwitchSettings;
  language: string;
  tunEnabled: boolean;
  acceptedPrivacyPolicyVersion: number;
};
