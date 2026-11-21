// Full profiles contain credentials and belong only to an open editor.
// Lists, home state and events use EngineProfileSummary.
export type EngineKind = "ssh" | "psiphon" | "tor" | "dns" | "amneziawg" | "ikev2";

export interface EngineProfileSummary {
  id: string;
  name: string;
  kind: EngineKind;
  version: number;
  revision: number;
}

export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  authType: "password" | "key";
  password: string;
  privateKey: string;
  keyPassphrase: string;
}

export interface PsiphonConfig {
  mode: "auto" | "cdn" | "direct";
  country: string;
  cdnIps: string[];
  cdnSni: string;
}

export interface TorConfig {
  bridgeMode: "none" | "default" | "custom";
  transport: "obfs4" | "snowflake" | "conjure";
  bridges: string;
}

export interface DNSConfig {
  engine: "dnstt" | "vaydns" | "masterdns";
  domain: string;
  domains: string[];
  publicKey: string;
  dnsTransport: "udp" | "tcp" | "dot" | "doh";
  resolvers: string[];
  dohUrl: string;
  socksUser: string;
  socksPass: string;
  encryptionMethod: number;
  encryptionKey: string;
}

export interface IKEv2Config {
  server: string;
  localId: string;
  serverId: string;
  authType: "eap_mschapv2" | "psk" | "certificate";
  username: string;
  password: string;
  psk: string;
  caCertPem: string;
  certificateThumbprint: string;
  certificateStore: "CurrentUser\\My" | "LocalMachine\\My";
}

type EngineConfig =
  | { kind: "ssh"; config: { ssh: SSHConfig } }
  | { kind: "psiphon"; config: { psiphon: PsiphonConfig } }
  | { kind: "tor"; config: { tor: TorConfig } }
  | { kind: "dns"; config: { dns: DNSConfig } }
  | { kind: "amneziawg"; config: { amneziawg: { config: string } } }
  | { kind: "ikev2"; config: { ikev2: IKEv2Config } };

export type EngineProfile = Omit<EngineProfileSummary, "kind"> & EngineConfig;

export interface EngineAvailability {
  kind: EngineKind;
  available: boolean;
  reason?: string;
  capabilities: {
    proxy: boolean;
    tun: boolean;
    native: boolean;
    udp: boolean;
    destinationRules: boolean;
    appSplit: boolean;
    customDns: boolean;
    lan: boolean;
    chain: boolean;
    country: boolean;
  };
}

export type RouteProfileRef =
  | { kind: "mihomo"; sourceId: string; nodeFingerprint?: string }
  | { kind: "engine"; profileId: string };
