package com.whitedns.vpn

import java.util.UUID

/** Selection identity is independent of subscription contents and engine credentials. */
sealed interface RouteProfileRef {
    data class Mihomo(val subscriptionId: String, val fingerprint: String) : RouteProfileRef
    data class Engine(val profileId: String) : RouteProfileRef
}

internal object RouteSelectionMigration {
    fun read(engineId: String?, subscriptionId: String, fingerprint: String): RouteProfileRef =
        engineId?.let(RouteProfileRef::Engine) ?: RouteProfileRef.Mihomo(subscriptionId, fingerprint)
}

sealed interface RouteProfile {
    data class Mihomo(val subscriptionId: String, val profile: ConnectionProfile) : RouteProfile
    data class Engine(val profile: EngineProfile) : RouteProfile
}

enum class EngineKind(val wireName: String, val title: String, val socks: Boolean) {
    SSH("ssh", "SSH", true), PSIPHON("psiphon", "Psiphon", true), TOR("tor", "Tor", true),
    DNS("dns", "DNS tunnels", true), OPENCONNECT("openconnect", "OpenConnect", false),
    IKEV2("ikev2", "IKEv2", false), AMNEZIAWG("amneziawg", "AmneziaWG", false);
    companion object {
        val selectable get() = entries.filter { it != OPENCONNECT }
        fun from(value: String): EngineKind = entries.firstOrNull { it.wireName == value }
            ?: throw IllegalArgumentException("Unknown engine")
    }
}

/** Each backend has a distinct configuration type; settings retain partner field names. */
sealed interface EngineConfig {
    val settings: Map<String, String>
    data class Ssh(override val settings: Map<String, String>) : EngineConfig
    data class Psiphon(override val settings: Map<String, String>) : EngineConfig
    data class Tor(override val settings: Map<String, String>) : EngineConfig
    data class DnsTunnel(override val settings: Map<String, String>) : EngineConfig
    data class OpenConnect(override val settings: Map<String, String>) : EngineConfig
    data class AmneziaWg(override val settings: Map<String, String>) : EngineConfig
    data class Ikev2(override val settings: Map<String, String>) : EngineConfig
    companion object {
        fun of(kind: EngineKind, settings: Map<String, String>): EngineConfig = when (kind) {
            EngineKind.SSH -> Ssh(settings)
            EngineKind.PSIPHON -> Psiphon(settings)
            EngineKind.TOR -> Tor(settings)
            EngineKind.DNS -> DnsTunnel(settings)
            EngineKind.OPENCONNECT -> OpenConnect(settings)
            EngineKind.IKEV2 -> Ikev2(settings)
            EngineKind.AMNEZIAWG -> AmneziaWg(settings)
        }
    }
}

data class EngineProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val kind: EngineKind,
    val config: EngineConfig,
    val version: Int = CURRENT_VERSION,
) {
    fun value(key: String, default: String = ""): String = config.settings[key] ?: default
    fun number(key: String, default: Int): Int = value(key).toIntOrNull() ?: default
    companion object {
        const val CURRENT_VERSION = 1
        const val SOURCE_ID = "saved-engines"
    }
}

data class EngineCapabilities(
    val proxyAccess: Boolean,
    val destinationRules: Boolean,
    val appSplitTunnel: Boolean,
    val customDns: Boolean,
    val lanSharing: Boolean,
    val udp: Boolean,
    val chains: Boolean = false,
) {
    companion object {
        fun forKind(kind: EngineKind) = when {
            kind == EngineKind.OPENCONNECT -> EngineCapabilities(false, false, false, false, false, false)
            kind.socks -> EngineCapabilities(true, true, true, true, true, false)
            kind == EngineKind.AMNEZIAWG -> EngineCapabilities(false, false, true, false, false, true)
            else -> EngineCapabilities(false, false, false, false, false, true)
        }
    }
}

sealed interface EngineAvailability {
    data object Available : EngineAvailability
    data class Unavailable(val reason: Reason) : EngineAvailability
    enum class Reason { ANDROID_VERSION, IPSEC_UNSUPPORTED, NATIVE_LIBRARY, TOR_TRANSPORT, TOR_ASSETS, RETIRED }
}

internal sealed interface BackendSessionPlan {
    data class Mihomo(val plan: SessionPlan) : BackendSessionPlan
    data class SocksEngine(val profile: EngineProfile) : BackendSessionPlan
    data class AmneziaWg(val profile: EngineProfile) : BackendSessionPlan
    data class PlatformIkev2(val profile: EngineProfile) : BackendSessionPlan
    companion object {
        fun forEngine(profile: EngineProfile): BackendSessionPlan = when {
            profile.kind.socks -> SocksEngine(profile)
            profile.kind == EngineKind.AMNEZIAWG -> AmneziaWg(profile)
            profile.kind == EngineKind.OPENCONNECT -> error("OpenConnect has been retired")
            else -> PlatformIkev2(profile)
        }
    }
}

internal object TorBridgeCompatibility {
    fun validate(transport: String, raw: String) {
        if (transport != "conjure") return
        raw.lineSequence().map { it.trim().removePrefix("Bridge ") }
            .filter { it.startsWith("conjure ") }.forEach { line ->
                val options = line.split(Regex("\\s+")).filter { it.contains('=') }
                    .associate { it.substringBefore('=') to it.substringAfter('=') }
                require(options["registrar"] == null || options["registrar"] == "http") {
                    "This Conjure client supports HTTP registration only"
                }
                require(options["transport"] == null || options["transport"] == "min") {
                    "This Conjure client supports min transport only"
                }
            }
    }
}

internal object EngineProfileValidation {
    fun validate(profile: EngineProfile) {
        require(profile.version == EngineProfile.CURRENT_VERSION) { "Unsupported profile version" }
        UUID.fromString(profile.id)
        require(profile.name.isNotBlank() && profile.name.length <= 100) { "A profile name is required" }
        require(profile.config == EngineConfig.of(profile.kind, profile.config.settings)) { "Engine configuration mismatch" }
        require(profile.config.settings.size <= 50 && profile.config.settings.values.all { it.length <= 65536 }) { "Profile is too large" }
        fun required(vararg keys: String) = keys.forEach { require(profile.value(it).isNotBlank()) { "Required: $it" } }
        fun port(key: String, fallback: Int) { require(profile.value(key, fallback.toString()).toIntOrNull() in 1..65535) { "Invalid port" } }
        when (profile.kind) {
            EngineKind.SSH -> {
                required("host", "username"); port("port", 22)
                require(profile.value("authType", "password") in setOf("password", "key")) { "Invalid authentication" }
                required(if (profile.value("authType", "password") == "key") "privateKey" else "password")
            }
            EngineKind.PSIPHON -> require(profile.value("mode", "auto") in setOf("auto", "cdn", "direct")) { "Invalid Psiphon mode" }
            EngineKind.TOR -> {
                require(profile.value("bridgeMode", "default") in setOf("none", "default", "custom")) { "Invalid bridge mode" }
                require(profile.value("transport", "obfs4") in setOf("obfs4", "snowflake", "conjure")) { "Invalid bridge transport" }
                if (profile.value("bridgeMode", "default") == "custom") {
                    required("bridges")
                    TorBridgeCompatibility.validate(profile.value("transport", "obfs4"), profile.value("bridges"))
                }
                require(profile.value("bridges").lineSequence().all { line ->
                    val s = line.trim(); s.isBlank() || (!s.contains('\u0000') && !s.contains('\r') &&
                        !s.contains('\"') && !s.contains('\\') && !s.startsWith("ClientTransportPlugin", true))
                }) { "Invalid bridge lines" }
            }
            EngineKind.DNS -> {
                require(profile.value("engine", "dnstt") in setOf("dnstt", "vaydns", "masterdns")) { "Invalid DNS engine" }
                if (profile.value("engine", "dnstt") == "masterdns") {
                    required("domains", "resolvers", "encryptionKey")
                    require(profile.number("encryptionMethod", 2) in 0..5) { "Invalid encryption method" }
                    require(profile.value("dnsTransport", "udp") == "udp") { "MasterDNS supports UDP resolvers" }
                } else {
                    required("domain", "publicKey")
                    require(profile.value("publicKey").matches(Regex("[0-9a-fA-F]{64}"))) { "Invalid server public key" }
                    require(profile.value("dnsTransport", "udp") in setOf("udp", "tcp", "dot", "doh")) { "Invalid DNS transport" }
                    if (profile.value("dnsTransport", "udp") == "doh") required("dohUrl") else required("resolvers")
                    require(profile.value("dohUrl", "https://dns.google/dns-query").startsWith("https://")) { "DoH requires HTTPS" }
                }
            }
            EngineKind.AMNEZIAWG -> { required("config"); AmneziaProfile.parse(profile.value("config")) }
            // Retain decoding of encrypted legacy profiles so users can delete them. Never start them.
            EngineKind.OPENCONNECT -> { required("server"); require(!profile.value("server").contains('\n')) { "Invalid gateway" } }
            EngineKind.IKEV2 -> {
                required("server")
                require(profile.value("authType", "eap_mschapv2") in setOf("eap_mschapv2", "psk", "certificate")) { "Invalid authentication" }
                when (profile.value("authType", "eap_mschapv2")) {
                    "psk" -> required("psk")
                    "certificate" -> required("userCertAlias")
                    else -> required("username", "password")
                }
            }
        }
    }
}

internal object EnginePreflight {
    fun validate(profile: EngineProfile, availability: EngineAvailability, tunnel: Boolean, lockdown: Boolean) {
        EngineProfileValidation.validate(profile)
        require(profile.kind != EngineKind.OPENCONNECT) { "OpenConnect has been retired" }
        require(availability == EngineAvailability.Available) { "Engine is unavailable on this device" }
        require(profile.kind.socks || tunnel) { "This engine requires VPN access" }
        // UID exclusion is needed by the child processes; Android lockdown forbids that bypass.
        require(!lockdown || !profile.kind.socks) { "This engine cannot run with Android VPN lockdown" }
    }
}
