package com.whitedns.vpn

import android.content.Context
import com.follow.clash.core.Core
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.net.URL
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLPeerUnverifiedException

object MihomoRuntimeDefaults {
    const val MIXED_PORT = 2080
    const val FALLBACK_CONTROL_PORT = 9090
    const val CONTROLLER_HOST = "127.0.0.1"
    const val DNS_LISTEN_PORT = 1053
    const val DELAY_TEST_URL = "https://www.gstatic.com/generate_204"
    val HEALTH_URLS = listOf(
        "https://valid-isrgrootx1.letsencrypt.org/",
        "https://connectivitycheck.gstatic.com/generate_204",
        "https://cloudflare.com/cdn-cgi/trace",
    )
    val HEALTH_URL = HEALTH_URLS.first()
    const val EGRESS_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
    const val SPEED_TEST_BYTES = 1_000_000L
    const val SPEED_TEST_URL_PREFIX = "https://speed.cloudflare.com/__down?bytes="
}

object TlsIntegrityPolicy {
    val TEST_URLS = MihomoRuntimeDefaults.HEALTH_URLS
    const val PROBE_TIMEOUT_MS = 2_000
    const val TOTAL_TIMEOUT_MS = 7_000L
    const val QUARANTINE_DURATION_MS = 24L * 60L * 60L * 1_000L

    fun endpointKey(endpoint: CleanIpResult): String = "${endpoint.ip}:${endpoint.port}"

    fun quarantineUntil(nowMs: Long): Long = nowMs + QUARANTINE_DURATION_MS

    fun isQuarantined(untilMs: Long, nowMs: Long): Boolean = untilMs > nowMs

    fun isCertificateFailure(error: Throwable): Boolean {
        return generateSequence(error) { it.cause }.any { cause ->
            cause is CertificateException ||
                cause is CertPathValidatorException ||
                cause is SSLPeerUnverifiedException
        }
    }
}

class TlsIntegrityPreferenceStore(context: Context) {
    private val prefs = context.getSharedPreferences("white_dns_tls_integrity", Context.MODE_PRIVATE)

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun saveEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
    }

    private companion object {
        const val KEY_ENABLED = "enabled"
    }
}

data class MihomoConnectionOptions(
    val amneziaNoiseEnabled: Boolean = false,
    val amneziaNoise: AmneziaNoiseSettings = MihomoConnectionOptionsPolicy.DEFAULT_NOISE,
)

object MihomoConnectionOptionsPolicy {
    const val MIN_NOISE_COUNT = 1
    const val MAX_NOISE_COUNT = 20
    const val MIN_NOISE_SIZE = 1
    const val MAX_NOISE_SIZE = 1280
    const val MIN_FAKE_TTL = 0
    const val MAX_FAKE_TTL = 255
    val DEFAULT_NOISE = AmneziaNoiseSettings(count = 5, minSize = 50, maxSize = 100)

    fun validateNoise(settings: AmneziaNoiseSettings): AmneziaNoiseSettings {
        val normalized = settings.copy(
            ipStackMode = settings.ipStackMode?.trim()?.lowercase()?.takeIf(String::isNotEmpty),
            congestionController = settings.congestionController?.trim()?.lowercase()?.takeIf(String::isNotEmpty),
            headerProtectionKey = settings.headerProtectionKey.trim(),
            contentPaddingAddition = settings.contentPaddingAddition.trim(),
            rekeyAfterTime = settings.rekeyAfterTime.trim(),
            rekeyTimeout = settings.rekeyTimeout.trim(),
            rejectAfterTime = settings.rejectAfterTime.trim(),
            keepaliveTimeout = settings.keepaliveTimeout.trim(),
            maxHandshakeAttempts = settings.maxHandshakeAttempts.trim(),
        )
        require(normalized.count in MIN_NOISE_COUNT..MAX_NOISE_COUNT) {
            "Count must be between $MIN_NOISE_COUNT and $MAX_NOISE_COUNT"
        }
        require(normalized.minSize in MIN_NOISE_SIZE..MAX_NOISE_SIZE) {
            "Minimum size must be between $MIN_NOISE_SIZE and $MAX_NOISE_SIZE"
        }
        require(normalized.maxSize in MIN_NOISE_SIZE..MAX_NOISE_SIZE) {
            "Maximum size must be between $MIN_NOISE_SIZE and $MAX_NOISE_SIZE"
        }
        require(normalized.minSize <= normalized.maxSize) { "Minimum size cannot exceed maximum size" }
        normalized.fakeTtl?.let {
            require(it in MIN_FAKE_TTL..MAX_FAKE_TTL) {
                "Fake TTL must be between $MIN_FAKE_TTL and $MAX_FAKE_TTL"
            }
        }
        normalized.version?.let { require(it == 0 || it == 3) { "Version must be 0 or 3" } }
        normalized.ipStackMode?.let {
            require(it in setOf("auto", "gvisor", "mips")) { "IP stack must be auto, gvisor, or mips" }
        }
        normalized.congestionController?.let {
            require(it in setOf("cubic", "reno", "bbr", "bbr3")) {
                "Congestion controller must be cubic, reno, bbr, or bbr3"
            }
        }
        val v3Configured = listOf(
            normalized.headerProtectionKey,
            normalized.contentPaddingAddition,
            normalized.rekeyAfterTime,
            normalized.rekeyTimeout,
            normalized.rejectAfterTime,
            normalized.keepaliveTimeout,
            normalized.maxHandshakeAttempts,
        ).any(String::isNotEmpty) || normalized.randomTrailers != null || normalized.disableCookies != null
        require(!v3Configured || normalized.version == 3) { "AmneziaWG v3 options require version 3" }
        require(
            listOf(
                normalized.headerProtectionKey,
                normalized.contentPaddingAddition,
                normalized.rekeyAfterTime,
                normalized.rekeyTimeout,
                normalized.rejectAfterTime,
                normalized.keepaliveTimeout,
                normalized.maxHandshakeAttempts,
            ).none { '\n' in it || '\r' in it },
        ) { "AmneziaWG values must fit on one line" }
        return normalized
    }

    fun isValidNoise(settings: AmneziaNoiseSettings): Boolean =
        runCatching { validateNoise(settings) }.isSuccess

    fun echCapable(type: String, tlsEnabled: Boolean, realityEnabled: Boolean): Boolean {
        if (realityEnabled) return false
        return when (type.lowercase()) {
            "trojan", "anytls", "trusttunnel", "tuic", "hysteria", "hysteria2" -> true
            "vless", "vmess" -> tlsEnabled
            else -> false
        }
    }

    fun applyTo(profile: ConnectionProfile, options: MihomoConnectionOptions): ConnectionProfile {
        return profile.copy(
            amneziaNoise = if (options.amneziaNoiseEnabled && profile.type.equals("wireguard", true)) {
                options.amneziaNoise
            } else {
                profile.amneziaNoise
            },
        )
    }
}

class MihomoConnectionOptionsPreferenceStore(context: Context) {
    private val prefs = context.getSharedPreferences("white_dns_connection_options", Context.MODE_PRIVATE)

    fun read(): MihomoConnectionOptions {
        val noise = AmneziaNoiseSettings(
            count = prefs.getInt(KEY_NOISE_COUNT, MihomoConnectionOptionsPolicy.DEFAULT_NOISE.count),
            minSize = prefs.getInt(KEY_NOISE_MIN_SIZE, MihomoConnectionOptionsPolicy.DEFAULT_NOISE.minSize),
            maxSize = prefs.getInt(KEY_NOISE_MAX_SIZE, MihomoConnectionOptionsPolicy.DEFAULT_NOISE.maxSize),
            fakeTtl = prefs.getInt(KEY_FAKE_TTL, 0).takeIf { prefs.contains(KEY_FAKE_TTL) },
            version = prefs.getInt(KEY_VERSION, 0).takeIf { prefs.contains(KEY_VERSION) },
            ipStackMode = prefs.getString(KEY_IP_STACK_MODE, null),
            congestionController = prefs.getString(KEY_CONGESTION_CONTROLLER, null),
            headerProtectionKey = prefs.getString(KEY_HEADER_PROTECTION_KEY, "").orEmpty(),
            contentPaddingAddition = prefs.getString(KEY_CONTENT_PADDING_ADDITION, "").orEmpty(),
            rekeyAfterTime = prefs.getString(KEY_REKEY_AFTER_TIME, "").orEmpty(),
            rekeyTimeout = prefs.getString(KEY_REKEY_TIMEOUT, "").orEmpty(),
            rejectAfterTime = prefs.getString(KEY_REJECT_AFTER_TIME, "").orEmpty(),
            keepaliveTimeout = prefs.getString(KEY_KEEPALIVE_TIMEOUT, "").orEmpty(),
            maxHandshakeAttempts = prefs.getString(KEY_MAX_HANDSHAKE_ATTEMPTS, "").orEmpty(),
            randomTrailers = prefs.getBoolean(KEY_RANDOM_TRAILERS, false)
                .takeIf { prefs.contains(KEY_RANDOM_TRAILERS) },
            disableCookies = prefs.getBoolean(KEY_DISABLE_COOKIES, false)
                .takeIf { prefs.contains(KEY_DISABLE_COOKIES) },
        ).takeIf(MihomoConnectionOptionsPolicy::isValidNoise) ?: MihomoConnectionOptionsPolicy.DEFAULT_NOISE
        return MihomoConnectionOptions(
            amneziaNoiseEnabled = prefs.getBoolean(KEY_AMNEZIA_NOISE_ENABLED, false),
            amneziaNoise = noise,
        )
    }

    fun saveAmneziaNoise(enabled: Boolean, settings: AmneziaNoiseSettings) {
        val valid = MihomoConnectionOptionsPolicy.validateNoise(settings)
        val editor = prefs.edit()
            .putBoolean(KEY_AMNEZIA_NOISE_ENABLED, enabled)
            .putInt(KEY_NOISE_COUNT, valid.count)
            .putInt(KEY_NOISE_MIN_SIZE, valid.minSize)
            .putInt(KEY_NOISE_MAX_SIZE, valid.maxSize)
        if (valid.fakeTtl == null) editor.remove(KEY_FAKE_TTL) else editor.putInt(KEY_FAKE_TTL, valid.fakeTtl)
        if (valid.version == null) editor.remove(KEY_VERSION) else editor.putInt(KEY_VERSION, valid.version)
        if (valid.ipStackMode == null) editor.remove(KEY_IP_STACK_MODE) else editor.putString(KEY_IP_STACK_MODE, valid.ipStackMode)
        if (valid.congestionController == null) {
            editor.remove(KEY_CONGESTION_CONTROLLER)
        } else {
            editor.putString(KEY_CONGESTION_CONTROLLER, valid.congestionController)
        }
        editor.putString(KEY_HEADER_PROTECTION_KEY, valid.headerProtectionKey)
            .putString(KEY_CONTENT_PADDING_ADDITION, valid.contentPaddingAddition)
            .putString(KEY_REKEY_AFTER_TIME, valid.rekeyAfterTime)
            .putString(KEY_REKEY_TIMEOUT, valid.rekeyTimeout)
            .putString(KEY_REJECT_AFTER_TIME, valid.rejectAfterTime)
            .putString(KEY_KEEPALIVE_TIMEOUT, valid.keepaliveTimeout)
            .putString(KEY_MAX_HANDSHAKE_ATTEMPTS, valid.maxHandshakeAttempts)
        if (valid.randomTrailers == null) {
            editor.remove(KEY_RANDOM_TRAILERS)
        } else {
            editor.putBoolean(KEY_RANDOM_TRAILERS, valid.randomTrailers)
        }
        if (valid.disableCookies == null) {
            editor.remove(KEY_DISABLE_COOKIES)
        } else {
            editor.putBoolean(KEY_DISABLE_COOKIES, valid.disableCookies)
        }
        editor.apply()
    }

    private companion object {
        const val KEY_AMNEZIA_NOISE_ENABLED = "amnezia_noise_enabled"
        const val KEY_NOISE_COUNT = "noise_count"
        const val KEY_NOISE_MIN_SIZE = "noise_min_size"
        const val KEY_NOISE_MAX_SIZE = "noise_max_size"
        const val KEY_FAKE_TTL = "noise_fake_ttl"
        const val KEY_VERSION = "amnezia_version"
        const val KEY_IP_STACK_MODE = "wireguard_ip_stack_mode"
        const val KEY_CONGESTION_CONTROLLER = "wireguard_congestion_controller"
        const val KEY_HEADER_PROTECTION_KEY = "amnezia_header_protection_key"
        const val KEY_CONTENT_PADDING_ADDITION = "amnezia_content_padding_addition"
        const val KEY_REKEY_AFTER_TIME = "amnezia_rekey_after_time"
        const val KEY_REKEY_TIMEOUT = "amnezia_rekey_timeout"
        const val KEY_REJECT_AFTER_TIME = "amnezia_reject_after_time"
        const val KEY_KEEPALIVE_TIMEOUT = "amnezia_keepalive_timeout"
        const val KEY_MAX_HANDSHAKE_ATTEMPTS = "amnezia_max_handshake_attempts"
        const val KEY_RANDOM_TRAILERS = "amnezia_random_trailers"
        const val KEY_DISABLE_COOKIES = "amnezia_disable_cookies"
    }
}

class TlsIntegrityException(cause: Throwable) : IOException("TLS certificate validation failed", cause)

enum class RoutingMode(val wireName: String, val labelRes: Int, val detailRes: Int) {
    Subscription("subscription", R.string.routing_mode_subscription, R.string.routing_mode_subscription_detail),
    IranBypass("iran", R.string.routing_mode_iran, R.string.routing_mode_iran_detail),
    GlobalProxy("global", R.string.routing_mode_global, R.string.routing_mode_global_detail),
    ;

    companion object {
        fun fromWireName(value: String?): RoutingMode {
            return values().firstOrNull { it.wireName == value } ?: Subscription
        }
    }
}

class RoutingModePreferenceStore(context: Context) {
    private val prefs = context.getSharedPreferences("white_dns_routing", Context.MODE_PRIVATE)

    fun read(): RoutingMode = RoutingMode.fromWireName(prefs.getString(KEY_MODE, null))

    fun save(mode: RoutingMode) {
        prefs.edit().putString(KEY_MODE, mode.wireName).apply()
    }

    private companion object {
        const val KEY_MODE = "mode"
    }
}

enum class DnsPrivacyMode(val wireName: String, val labelRes: Int) {
    Automatic("automatic", R.string.dns_mode_automatic),
    DoH("doh", R.string.dns_mode_doh),
    DoT("dot", R.string.dns_mode_dot),
    ;

    companion object {
        fun fromWireName(value: String?): DnsPrivacyMode {
            return values().firstOrNull { it.wireName == value } ?: Automatic
        }
    }
}

object DnsPrivacyPolicy {
    const val DEFAULT_DOH_URL = "https://1.1.1.1/dns-query"
    const val DEFAULT_DOT_ENDPOINT = "tls://1.1.1.1:853"

    fun normalizeDohUrl(value: String): String {
        val input = value.trim()
        val uri = runCatching { URI(input) }
            .getOrElse { throw IllegalArgumentException("DoH باید یک URL معتبر HTTPS باشد") }
        require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()) {
            "DoH باید یک URL معتبر HTTPS باشد"
        }
        require(uri.rawUserInfo == null && uri.rawFragment == null) {
            "URL مربوط به DoH نباید اطلاعات ورود یا fragment داشته باشد"
        }
        require(uri.rawAuthority?.endsWith(':') == false) { "پورت DoH باید عددی بین 1 تا 65535 باشد" }
        require(uri.port == -1 || uri.port in 1..65535) { "پورت DoH باید عددی بین 1 تا 65535 باشد" }
        return uri.toASCIIString()
    }

    fun normalizeDotEndpoint(value: String): String {
        val input = value.trim()
        val uri = runCatching {
            URI(if (input.startsWith("tls://", ignoreCase = true)) input else "tls://$input")
        }.getOrElse { throw IllegalArgumentException("DoT باید یک host[:port] معتبر باشد") }
        require(uri.scheme.equals("tls", ignoreCase = true) && !uri.host.isNullOrBlank()) {
            "DoT باید یک host[:port] معتبر باشد"
        }
        require(
            uri.rawUserInfo == null &&
                uri.rawQuery == null &&
                uri.rawFragment == null &&
                (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/"),
        ) {
            "DoT فقط می‌تواند نام میزبان و پورت اختیاری داشته باشد"
        }
        require(uri.rawAuthority?.endsWith(':') == false) { "پورت DoT باید عددی بین 1 تا 65535 باشد" }
        require(uri.port == -1 || uri.port in 1..65535) { "پورت DoT باید عددی بین 1 تا 65535 باشد" }
        val port = uri.port.takeIf { it != -1 } ?: 853
        val host = when {
            uri.host.startsWith('[') -> uri.host
            uri.host.contains(':') -> "[${uri.host}]"
            else -> uri.host
        }
        return "tls://$host:$port"
    }
}

class DnsPrivacyPreferenceStore(context: Context) {
    private val prefs = context.getSharedPreferences("white_dns_privacy", Context.MODE_PRIVATE)

    fun readMode(): DnsPrivacyMode = DnsPrivacyMode.fromWireName(prefs.getString(KEY_MODE, null))

    fun readDohUrl(): String {
        return runCatching {
            DnsPrivacyPolicy.normalizeDohUrl(prefs.getString(KEY_DOH_URL, null) ?: DnsPrivacyPolicy.DEFAULT_DOH_URL)
        }.getOrDefault(DnsPrivacyPolicy.DEFAULT_DOH_URL)
    }

    fun readDotEndpoint(): String {
        return runCatching {
            DnsPrivacyPolicy.normalizeDotEndpoint(
                prefs.getString(KEY_DOT_ENDPOINT, null) ?: DnsPrivacyPolicy.DEFAULT_DOT_ENDPOINT,
            )
        }.getOrDefault(DnsPrivacyPolicy.DEFAULT_DOT_ENDPOINT)
    }

    fun saveMode(mode: DnsPrivacyMode) {
        prefs.edit().putString(KEY_MODE, mode.wireName).apply()
    }

    fun saveDohUrl(value: String) {
        prefs.edit().putString(KEY_DOH_URL, DnsPrivacyPolicy.normalizeDohUrl(value)).apply()
    }

    fun saveDotEndpoint(value: String) {
        prefs.edit().putString(KEY_DOT_ENDPOINT, DnsPrivacyPolicy.normalizeDotEndpoint(value)).apply()
    }

    private companion object {
        const val KEY_MODE = "mode"
        const val KEY_DOH_URL = "doh_url"
        const val KEY_DOT_ENDPOINT = "dot_endpoint"
    }
}

object MihomoDelayPolicy {
    fun acceptedDelayMs(delayMs: Int?): Long? {
        return delayMs?.takeIf { it > 0 }?.toLong()
    }
}

object MihomoControllerPort {
    fun allocate(): Int {
        return LocalTcpPort.allocate(MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT)
    }

    fun canBind(port: Int): Boolean {
        return LocalTcpPort.canBind(MihomoRuntimeDefaults.CONTROLLER_HOST, port)
    }
}

object DpiBypassPort {
    fun allocate(): Int {
        return LocalTcpPort.allocate(DpiBypassDefaults.FALLBACK_PROXY_PORT)
    }

    fun canBind(port: Int): Boolean {
        return LocalTcpPort.canBind(DpiBypassDefaults.PROXY_HOST, port)
    }
}

private object LocalTcpPort {
    fun allocate(fallbackPort: Int): Int {
        return runCatching {
            ServerSocket(0).use { socket ->
                socket.reuseAddress = true
                socket.localPort
            }
        }.getOrDefault(fallbackPort)
    }

    fun canBind(host: String, port: Int): Boolean {
        return runCatching {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(host, port))
            }
        }.isSuccess
    }
}

data class MihomoRuntimePaths(
    val baseDir: File,
    val runtimeConfigYaml: File,
    val profileYaml: File,
    val serviceJson: File,
    val patchFinalJson: File,
    val setupParamsJson: File,
    val logFile: File,
    val errorFile: File,
    val cacheDir: File,
    val secret: String,
    val controlPort: Int,
)

internal object MihomoGeoDataInstaller {
    val fileNames = listOf("GEOIP.metadb", "GEOIP.dat", "GEOSITE.dat", "ASN.mmdb")

    @Synchronized
    fun install(baseDir: File, openAsset: (String) -> InputStream): List<String> {
        baseDir.mkdirs()
        return fileNames.mapNotNull { fileName ->
            val target = File(baseDir, fileName)
            val existing = baseDir.listFiles()?.firstOrNull { candidate ->
                candidate.name.equals(fileName, ignoreCase = true)
            }
            if (existing?.isFile == true && existing.length() > 0L) return@mapNotNull null

            val temporary = File(baseDir, ".$fileName.tmp")
            try {
                openAsset("data/$fileName").use { input ->
                    temporary.outputStream().buffered().use { output -> input.copyTo(output) }
                }
                listOfNotNull(existing, target.takeIf { it != existing && it.exists() }).forEach { stale ->
                    if (!stale.delete()) {
                        throw IOException("Unable to replace Mihomo geodata file ${stale.name}")
                    }
                }
                if (!temporary.renameTo(target)) {
                    throw IOException("Unable to install Mihomo geodata file $fileName")
                }
                fileName
            } finally {
                temporary.delete()
            }
        }
    }
}

internal data class ProfileTestRuntimePlan(
    val rawYaml: String,
    val routingMode: RoutingMode,
    val dns: DnsRuntimeSettings,
)

internal data class MihomoRuntimeDocument(
    val rawYaml: String,
    val splitTunnelPlan: SplitTunnelRuntimePlan,
    val lanSharing: LanSharingSettings,
    val routingMode: RoutingMode,
    val dns: DnsRuntimeSettings,
    val selectedMap: Map<String, String>,
    val rejectProxiedUdp: Boolean = false,
)

internal fun SessionPlan.toMihomoRuntimeDocument(): MihomoRuntimeDocument = MihomoRuntimeDocument(
    rawYaml = runtimeYaml,
    splitTunnelPlan = splitTunnelPlan,
    lanSharing = lanSharing,
    routingMode = routingMode,
    dns = dns,
    selectedMap = selectedMap,
)

internal class MihomoRuntimeConfigBuilder(private val context: Context) {
    fun write(
        plan: SessionPlan,
        secret: String = MihomoControllerSecret.generate(),
    ): MihomoRuntimePaths = write(
        document = plan.toMihomoRuntimeDocument(),
        secret = secret,
    )

    fun writeProfileTest(
        plan: ProfileTestRuntimePlan,
        secret: String = MihomoControllerSecret.generate(),
    ): MihomoRuntimePaths = write(
        document = MihomoRuntimeDocument(
            rawYaml = plan.rawYaml,
            splitTunnelPlan = SplitTunnelRuntimePlan.off(),
            lanSharing = LanSharingSettings(),
            routingMode = plan.routingMode,
            dns = plan.dns,
            selectedMap = emptyMap(),
        ),
        secret = secret,
    )

    internal fun write(
        document: MihomoRuntimeDocument,
        secret: String,
    ): MihomoRuntimePaths {
        val baseDir = File(context.filesDir, "mihomo").apply { mkdirs() }
        val cacheDir = File(context.cacheDir, "mihomo").apply { mkdirs() }
        val runtimeConfigYaml = File(baseDir, "config.yaml")
        val profileYaml = File(baseDir, "service_core_runtime_profile.yaml")
        val patchFinal = File(baseDir, "service_core_patch_final.json")
        val setupParams = File(baseDir, "service_core_setup_params.json")
        val logFile = File(baseDir, "service_core.log")
        val errorFile = DiagnosticLogger.mihomoStderrFile(context)
        val serviceJson = File(context.filesDir, "service.json")
        val controlPort = MihomoControllerPort.allocate()
        DiagnosticLogger.info(
            context,
            "mihomo.controller.port",
            "selected=$controlPort bindable=${MihomoControllerPort.canBind(controlPort)} fallback=${controlPort == MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT}",
        )

        profileYaml.writeText(document.rawYaml)
        runtimeConfigYaml.writeText(
            flClashRuntimeYaml(
                rawYaml = document.rawYaml,
                secret = secret,
                controlPort = controlPort,
                lanSharing = document.lanSharing,
                routingMode = document.routingMode,
                dnsPrivacyMode = document.dns.mode,
                dohUrl = document.dns.dohUrl,
                dotEndpoint = document.dns.dotEndpoint,
                rejectProxiedUdp = document.rejectProxiedUdp,
            ),
        )
        patchFinal.writeText(
            corePatchJson(
                document.splitTunnelPlan,
                secret,
                controlPort,
                document.lanSharing,
            ).toString(2),
        )
        setupParams.writeText(setupParamsJson(document.selectedMap).toString(2))
        serviceJson.writeText(
            serviceJson(
                appName = context.getString(R.string.app_name),
                versionName = BuildConfig.VERSION_NAME,
                baseDir = baseDir.absolutePath,
                cacheDir = cacheDir.absolutePath,
                profileYaml = profileYaml.absolutePath,
                patchFinal = patchFinal.absolutePath,
                logFile = logFile.absolutePath,
                errorFile = errorFile.absolutePath,
                secret = secret,
                controlPort = controlPort,
            ).toString(2),
        )
        File(context.filesDir, "vpn_profile.txt").writeText(profileYaml.absolutePath)
        logFile.parentFile?.mkdirs()
        errorFile.parentFile?.mkdirs()

        return MihomoRuntimePaths(
            baseDir = baseDir,
            runtimeConfigYaml = runtimeConfigYaml,
            profileYaml = profileYaml,
            serviceJson = serviceJson,
            patchFinalJson = patchFinal,
            setupParamsJson = setupParams,
            logFile = logFile,
            errorFile = errorFile,
            cacheDir = cacheDir,
            secret = secret,
            controlPort = controlPort,
        )
    }

    fun corePatchJson(
        splitTunnelPlan: SplitTunnelRuntimePlan,
        secret: String,
        controlPort: Int = MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT,
        lanSharing: LanSharingSettings = LanSharingSettings(),
    ): JSONObject {
        return corePatchJson(context.getString(R.string.app_name), splitTunnelPlan, secret, controlPort, lanSharing)
    }

    companion object {
        fun corePatchJson(
            appName: String,
            splitTunnelPlan: SplitTunnelRuntimePlan,
            secret: String,
            controlPort: Int = MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT,
            lanSharing: LanSharingSettings = LanSharingSettings(),
        ): JSONObject {
            val tun = JSONObject()
                .put("enable", false)

            return JSONObject()
                .put("mixed-port", MihomoRuntimeDefaults.MIXED_PORT)
                .put(
                    "external-controller",
                    "${MihomoRuntimeDefaults.CONTROLLER_HOST}:$controlPort",
                )
                .put("secret", secret)
                .put("allow-lan", lanSharing.enabled)
                .apply {
                    if (lanSharing.enabled) {
                        put("bind-address", "0.0.0.0")
                        if (lanSharing.passwordRequired) {
                            put("authentication", JSONArray(listOf("${lanSharing.username}:${lanSharing.password}")))
                            put("skip-auth-prefixes", JSONArray(listOf("127.0.0.0/8")))
                        }
                        put("lan-allowed-ips", JSONArray(LAN_ALLOWED_IPS))
                    }
                }
                .put("mode", "rule")
                .put("log-level", "warning")
                .put("ipv6", false)
                .put("unified-delay", true)
                .put("global-client-fingerprint", "chrome")
                .put("tun", tun)
        }

        fun serviceJson(
            appName: String,
            versionName: String,
            baseDir: String,
            cacheDir: String,
            profileYaml: String,
            patchFinal: String,
            logFile: String,
            errorFile: String,
            secret: String,
            controlPort: Int = MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT,
        ): JSONObject {
            return JSONObject()
                .put("control_port", controlPort)
                .put("base_dir", baseDir)
                .put("work_dir", "")
                .put("cache_dir", cacheDir)
                .put("core_path", profileYaml)
                .put("core_path_patch", "")
                .put("core_path_patch_final", patchFinal)
                .put("log_path", logFile)
                .put("err_path", errorFile)
                .put("id", secret.take(16))
                .put("version", versionName)
                .put("name", appName)
                .put("secret", secret)
                .put("install_refer", "")
                .put("prepare", true)
                .put("wake_lock", false)
                .put("auto_connect_at_boot", false)
                .put("include_all_networks", false)
                .put("exclude_local_networks", false)
                .put("exclude_cellular_services", false)
                .put("exclude_apns", false)
                .put("exclude_device_communication", false)
                .put("enforce_routes", false)
                .put("auto_route_use_sub_ranges_by_default", false)
        }

        fun initParamsJson(baseDir: String, sdkInt: Int): JSONObject {
            return JSONObject()
                .put("home-dir", baseDir)
                .put("version", sdkInt)
        }

        fun setupParamsJson(
            selectedMap: Map<String, String> = emptyMap(),
            testUrl: String = MihomoRuntimeDefaults.DELAY_TEST_URL,
        ): JSONObject {
            return JSONObject()
                .put("selected-map", JSONObject(selectedMap))
                .put("test-url", testUrl)
        }

        fun flClashRuntimeYaml(
            rawYaml: String,
            secret: String,
            controlPort: Int = MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT,
            lanSharing: LanSharingSettings = LanSharingSettings(),
            routingMode: RoutingMode = RoutingMode.Subscription,
            dnsPrivacyMode: DnsPrivacyMode = DnsPrivacyMode.Automatic,
            dohUrl: String = DnsPrivacyPolicy.DEFAULT_DOH_URL,
            dotEndpoint: String = DnsPrivacyPolicy.DEFAULT_DOT_ENDPOINT,
            rejectProxiedUdp: Boolean = false,
        ): String {
            val routingTarget = routingTarget(rawYaml)
            val requiredRoutingTarget = if (routingMode == RoutingMode.Subscription) {
                null
            } else {
                requireNotNull(routingTarget) {
                    "Routing mode '${routingMode.wireName}' requires a usable proxy or proxy group"
                }
            }
            val keysToReplace = if (routingMode == RoutingMode.Subscription) {
                FLCLASH_OVERRIDE_KEYS
            } else {
                FLCLASH_OVERRIDE_KEYS + ROUTING_OVERRIDE_KEYS
            }
            val subscriptionYaml = stripTopLevelKeys(rawYaml, keysToReplace)
            val dnsProxyGroup = if (routingMode == RoutingMode.Subscription) {
                routingTarget
            } else {
                requiredRoutingTarget
            }
            val proxySuffix = dnsProxyGroup?.let { "#$it" }.orEmpty()
            val dnsServers = when (dnsPrivacyMode) {
                DnsPrivacyMode.Automatic -> DOH_SERVERS + DOT_SERVERS
                DnsPrivacyMode.DoH -> listOf(DnsPrivacyPolicy.normalizeDohUrl(dohUrl))
                DnsPrivacyMode.DoT -> listOf(DnsPrivacyPolicy.normalizeDotEndpoint(dotEndpoint))
            }
            val bootstrapServers = when (dnsPrivacyMode) {
                DnsPrivacyMode.Automatic, DnsPrivacyMode.DoH -> DOH_SERVERS
                DnsPrivacyMode.DoT -> DOT_SERVERS
            }
            return buildString {
                if (subscriptionYaml.isNotBlank()) {
                    append(subscriptionYaml.trimEnd())
                    append("\n\n")
                }
                when (routingMode) {
                    RoutingMode.Subscription -> Unit
                    RoutingMode.IranBypass -> {
                        append("rule-providers:\n")
                        append("  whitedns-iran:\n")
                        append("    type: http\n")
                        append("    behavior: classical\n")
                        append("    format: text\n")
                        append("    url: $IRAN_RULESET_URL\n")
                        append("    path: ./ruleset/whitedns-iran.txt\n")
                        append("    interval: 86400\n")
                        append("    proxy: ${yamlSingleQuoted(requiredRoutingTarget!!)}\n")
                        append("    size-limit: 10485760\n")
                        append("rules:\n")
                        append("  - 'RULE-SET,whitedns-iran,DIRECT'\n")
                        if (rejectProxiedUdp) append("  - 'NETWORK,UDP,REJECT'\n")
                        append("  - ${yamlSingleQuoted("MATCH,$requiredRoutingTarget")}\n\n")
                    }
                    RoutingMode.GlobalProxy -> {
                        append("rules:\n")
                        if (rejectProxiedUdp) append("  - 'NETWORK,UDP,REJECT'\n")
                        append("  - ${yamlSingleQuoted("MATCH,$requiredRoutingTarget")}\n\n")
                    }
                }
                append("# WhiteDNS Android runtime overrides\n")
                append("mixed-port: ${MihomoRuntimeDefaults.MIXED_PORT}\n")
                append("external-controller: ${MihomoRuntimeDefaults.CONTROLLER_HOST}:$controlPort\n")
                append("secret: \"${secret}\"\n")
                append("allow-lan: ${lanSharing.enabled}\n")
                if (lanSharing.enabled) {
                    append("bind-address: 0.0.0.0\n")
                    if (lanSharing.passwordRequired) {
                        append("authentication:\n")
                        append("  - ${yamlSingleQuoted("${lanSharing.username}:${lanSharing.password}")}\n")
                        append("skip-auth-prefixes:\n")
                        append("  - 127.0.0.0/8\n")
                    }
                    append("lan-allowed-ips:\n")
                    LAN_ALLOWED_IPS.forEach { append("  - $it\n") }
                }
                append("mode: rule\n")
                append("log-level: warning\n")
                append("ipv6: false\n")
                append("unified-delay: true\n")
                append("global-client-fingerprint: chrome\n")
                append("dns:\n")
                append("  enable: true\n")
                // Loopback only: `allow-lan: false` gates the proxy listeners but not this one, so
                // binding 0.0.0.0 would expose an open resolver to every peer on the same Wi-Fi.
                append("  listen: ${MihomoRuntimeDefaults.CONTROLLER_HOST}:${MihomoRuntimeDefaults.DNS_LISTEN_PORT}\n")
                append("  ipv6: false\n")
                append("  respect-rules: ${dnsProxyGroup != null}\n")
                append("  enhanced-mode: fake-ip\n")
                append("  fake-ip-range: 198.18.0.1/16\n")
                append("  default-nameserver:\n")
                bootstrapServers.forEach { server ->
                    append("    - ${yamlSingleQuoted(server)}\n")
                }
                append("  nameserver:\n")
                dnsServers.forEach { server ->
                    append("    - ${yamlSingleQuoted("$server$proxySuffix")}\n")
                }
                append("  proxy-server-nameserver:\n")
                bootstrapServers.forEach { server ->
                    append("    - ${yamlSingleQuoted(server)}\n")
                }
                append("tun:\n")
                append("  enable: false\n")
            }
        }

        private fun routingTarget(rawYaml: String): String? {
            return runCatching {
                val summary = MihomoConfigParser.parseSummary(rawYaml)
                MihomoSelectionPolicy.trafficProbeGroup(summary)?.name
                    ?: MihomoSelectionPolicy.mainSelectorGroup(summary)?.name
                    ?: summary.proxies.firstOrNull()?.name
            }.getOrNull()
        }

        private fun yamlSingleQuoted(value: String): String {
            return "'${value.replace("'", "''")}'"
        }

        private fun stripTopLevelKeys(rawYaml: String, keys: Set<String>): String {
            val output = mutableListOf<String>()
            var skipping = false

            rawYaml.replace("\r\n", "\n").replace('\r', '\n').lineSequence().forEach { line ->
                val key = topLevelKey(line)
                if (skipping) {
                    val topLevelBoundary = key != null || (line.isNotBlank() && line.first().isWhitespace().not())
                    if (!topLevelBoundary) return@forEach
                    skipping = false
                }

                if (key in keys) {
                    skipping = true
                    return@forEach
                }
                output += line
            }

            return output.joinToString("\n").trimEnd()
        }

        private fun topLevelKey(line: String): String? {
            if (line.isBlank() || line.first().isWhitespace() || line.trimStart().startsWith("#")) return null
            val index = line.indexOf(':')
            if (index <= 0) return null
            return line.substring(0, index).trim().takeIf { it.isNotBlank() }
        }

        private val FLCLASH_OVERRIDE_KEYS = setOf(
            "mixed-port",
            "external-controller",
            "secret",
            "allow-lan",
            "bind-address",
            "authentication",
            "skip-auth-prefixes",
            "lan-allowed-ips",
            "lan-disallowed-ips",
            "mode",
            "log-level",
            "ipv6",
            "unified-delay",
            "global-client-fingerprint",
            "dns",
            "tun",
            // Android installs bundled geodata; subscriptions cannot start native updaters.
            "geo-auto-update",
            "geo-update-interval",
            "geox-url",
        )
        private val ROUTING_OVERRIDE_KEYS = setOf("rules", "rule-providers", "sub-rules")
        private const val IRAN_RULESET_URL =
            "https://github.com/ygbkm/clash-rules-iran/releases/latest/download/rules.txt"

        private val DOH_SERVERS = listOf(
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
        )
        private val DOT_SERVERS = listOf(
            "tls://1.1.1.1:853",
            "tls://8.8.8.8:853",
        )
        private val LAN_ALLOWED_IPS = listOf(
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
        )
    }
}

data class MihomoAutomaticRoutingBridgeResult(
    val yaml: String,
    val applied: Boolean,
    val rootName: String?,
    val targetName: String?,
    val reason: String,
)

object MihomoAutomaticRoutingBridge {
    fun patch(rawYaml: String): MihomoAutomaticRoutingBridgeResult {
        val normalized = rawYaml.replace("\r\n", "\n").replace('\r', '\n')
        val lines = normalized.split('\n')
        val blocks = parseGroupBlocks(lines)
        val summary = runCatching { MihomoConfigParser.parseSummary(rawYaml) }.getOrNull()
            ?: return result(rawYaml, reason = "invalid-config")
        val rawTrafficBlocks = blocks.filter { it.name?.contains("WhiteDNS Proxy", ignoreCase = true) == true }
        if (rawTrafficBlocks.size > 1) {
            return result(rawYaml, reason = "root-layout-ambiguous")
        }
        if (rawTrafficBlocks.singleOrNull()?.inline == true) {
            return result(
                rawYaml,
                rootName = rawTrafficBlocks.single().name,
                reason = "root-layout-unsupported",
            )
        }
        val root = MihomoSelectionPolicy.trafficProbeGroup(summary)
            ?: MihomoSelectionPolicy.mainSelectorGroup(summary)
            ?: return result(rawYaml, reason = "root-not-found")
        if (!root.type.equals("select", ignoreCase = true)) {
            return result(rawYaml, rootName = root.name, reason = "root-not-selector")
        }

        val target = MihomoSelectionPolicy.autoGroup(summary)
            ?: return result(rawYaml, rootName = root.name, reason = "auto-group-not-found")
        if (normalizeType(target.type) != URL_TEST_TYPE) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "auto-group-not-url-test",
            )
        }
        if (target.name == root.name) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "target-is-root",
            )
        }

        val rootBlocks = blocks.filter { it.name == root.name }
        val targetBlocks = blocks.filter { it.name == target.name }
        if (rootBlocks.size != 1 || targetBlocks.size != 1) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "group-layout-ambiguous",
            )
        }

        val blocksByName = blocks.filter { it.name != null }.groupBy { requireNotNull(it.name) }
        val knownGroupNames = summary.groups.mapTo(mutableSetOf(), MihomoProxyGroup::name).apply {
            addAll(blocks.mapNotNull(GroupBlock::name))
        }
        val reachability = targetReachability(
            lines = lines,
            blocksByName = blocksByName,
            knownGroupNames = knownGroupNames,
            rootName = root.name,
            targetName = target.name,
        )
        if (reachability == TargetReachability.Reachable) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "already-reachable",
            )
        }
        if (reachability == TargetReachability.Unsupported) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "membership-layout-unsupported",
            )
        }

        val rootProxiesIndex = groupMembership(lines, rootBlocks.single())?.proxiesIndex
        if (rootProxiesIndex == null) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "root-proxies-unsupported",
            )
        }

        val patched = lines.toMutableList()
        patched.add(rootProxiesIndex + 1, "      - ${yamlSingleQuoted(target.name)}")
        val patchedYaml = patched.joinToString("\n")
        val patchedSummary = runCatching { MihomoConfigParser.parseSummary(patchedYaml) }.getOrNull()
        val postPatchValid = patchedSummary != null &&
            nameTypeCounts(summary.proxies.map { it.name to it.type }) ==
            nameTypeCounts(patchedSummary.proxies.map { it.name to it.type }) &&
            nameTypeCounts(summary.groups.map { it.name to it.type }) ==
            nameTypeCounts(patchedSummary.groups.map { it.name to it.type }) &&
            patchedSummary.groups.any { it.name == root.name && it.type == root.type } &&
            patchedSummary.groups.any { it.name == target.name && it.type == target.type }
        if (!postPatchValid) {
            return result(
                rawYaml,
                rootName = root.name,
                targetName = target.name,
                reason = "post-patch-validation-failed",
            )
        }
        return MihomoAutomaticRoutingBridgeResult(
            yaml = patchedYaml,
            applied = true,
            rootName = root.name,
            targetName = target.name,
            reason = "inserted",
        )
    }

    private data class GroupBlock(
        val start: Int,
        val endExclusive: Int,
        val name: String?,
        val inline: Boolean,
    )

    private data class GroupMembership(
        val proxiesIndex: Int?,
        val members: List<String>,
    )

    private data class PendingGroup(
        val name: String,
        val depth: Int,
        val path: Set<String>,
    )

    private enum class TargetReachability {
        Reachable,
        Unreachable,
        Unsupported,
    }

    private fun parseGroupBlocks(lines: List<String>): List<GroupBlock> {
        val sectionIndexes = lines.indices.filter { index -> topLevelKey(lines[index]) == "proxy-groups" }
        if (sectionIndexes.size != 1) return emptyList()
        val sectionStart = sectionIndexes.single()
        val sectionEnd = (sectionStart + 1 until lines.size).firstOrNull { index ->
            topLevelKey(lines[index]) != null
        } ?: lines.size
        val starts = (sectionStart + 1 until sectionEnd).filter { index ->
            indentation(lines[index]) == 2 && lines[index].trimStart().startsWith("- ")
        }
        return starts.mapIndexed { blockIndex, start ->
            val endExclusive = starts.getOrNull(blockIndex + 1) ?: sectionEnd
            val inline = lines[start].trimStart().startsWith("- {")
            GroupBlock(
                start = start,
                endExclusive = endExclusive,
                name = groupName(lines, start, endExclusive, inline),
                inline = inline,
            )
        }
    }

    private fun groupName(lines: List<String>, start: Int, endExclusive: Int, inline: Boolean): String? {
        if (inline) {
            return Regex("""(?:^|[,{]\s*)['\"]?name['\"]?\s*:\s*([^,}]+)""")
                .find(lines[start].trimStart().removePrefix("- "))
                ?.groupValues
                ?.get(1)
                ?.let(::decodeYamlScalar)
        }
        for (index in start until endExclusive) {
            val content = lines[index].trimStart()
            val value = when {
                index == start && content.startsWith("- name:") -> content.substringAfter("- name:")
                indentation(lines[index]) == 4 && content.startsWith("name:") -> content.substringAfter("name:")
                else -> null
            }
            value?.let { return decodeYamlScalar(it) }
        }
        return null
    }

    private fun targetReachability(
        lines: List<String>,
        blocksByName: Map<String, List<GroupBlock>>,
        knownGroupNames: Set<String>,
        rootName: String,
        targetName: String,
    ): TargetReachability {
        val pending = mutableListOf(PendingGroup(rootName, depth = 0, path = setOf(rootName)))
        val visited = mutableSetOf<String>()
        var unsupported = false
        var pendingIndex = 0
        while (pendingIndex < pending.size) {
            val current = pending[pendingIndex++]
            if (!visited.add(current.name)) continue
            val blocks = blocksByName[current.name]
            if (blocks?.size != 1) {
                unsupported = true
                continue
            }
            val membership = groupMembership(lines, blocks.single())
            if (membership == null) {
                unsupported = true
                continue
            }
            for (member in membership.members) {
                if (member == targetName) return TargetReachability.Reachable
                if (member !in knownGroupNames) continue
                if (member in current.path || current.depth + 1 >= MAX_GROUP_DEPTH) {
                    unsupported = true
                    continue
                }
                pending += PendingGroup(
                    name = member,
                    depth = current.depth + 1,
                    path = current.path + member,
                )
            }
        }
        return if (unsupported) TargetReachability.Unsupported else TargetReachability.Unreachable
    }

    private fun groupMembership(lines: List<String>, block: GroupBlock): GroupMembership? {
        if (block.inline) return null
        val proxiesFields = (block.start until block.endExclusive).filter { index ->
            indentation(lines[index]) == 4 && fieldName(lines[index]) == "proxies"
        }
        if (proxiesFields.size > 1) return null
        if (proxiesFields.size == 1) {
            val proxiesIndex = proxiesFields.single()
            if (fieldValue(lines[proxiesIndex]).isNotEmpty()) return null
            val members = blockListValues(lines, proxiesIndex, block.endExclusive) ?: return null
            return GroupMembership(proxiesIndex = proxiesIndex, members = members)
        }

        val includeAllFields = (block.start until block.endExclusive).filter { index ->
            indentation(lines[index]) == 4 && fieldName(lines[index]) == "include-all"
        }
        val useFields = (block.start until block.endExclusive).filter { index ->
            indentation(lines[index]) == 4 && fieldName(lines[index]) == "use"
        }
        if (includeAllFields.size > 1 || useFields.size > 1) return null
        val includesAll = includeAllFields.singleOrNull()?.let { index ->
            if (!fieldValue(lines[index]).equals("true", ignoreCase = true)) return null
            true
        } ?: false
        val hasProviderUse = useFields.singleOrNull()?.let { index ->
            if (fieldValue(lines[index]).isNotEmpty()) return null
            val providers = blockListValues(lines, index, block.endExclusive) ?: return null
            if (providers.isEmpty()) return null
            true
        } ?: false
        if (!includesAll && !hasProviderUse) return null
        return GroupMembership(proxiesIndex = null, members = emptyList())
    }

    private fun blockListValues(lines: List<String>, fieldIndex: Int, blockEndExclusive: Int): List<String>? {
        val listEnd = (fieldIndex + 1 until blockEndExclusive).firstOrNull { index ->
            val line = lines[index]
            line.isNotBlank() && !line.trimStart().startsWith("#") && indentation(line) <= 4
        } ?: blockEndExclusive
        val significantLines = (fieldIndex + 1 until listEnd).filter { index ->
            lines[index].isNotBlank() && !lines[index].trimStart().startsWith("#")
        }
        if (significantLines.any { index ->
                indentation(lines[index]) != 6 || !lines[index].trimStart().startsWith("- ")
            }
        ) {
            return null
        }
        val members = significantLines.map { index ->
            decodeYamlScalar(lines[index].trimStart().removePrefix("- ")) ?: return null
        }
        if (members.any(String::isBlank)) return null
        return members
    }

    private fun fieldValue(line: String): String =
        line.substringAfter(':', "").substringBefore(" #").trim()

    private fun normalizeType(type: String): String = type.lowercase().filter(Char::isLetterOrDigit)

    private fun decodeYamlScalar(value: String): String? {
        val trimmed = value.trim().substringBefore(" #").trim()
        if (trimmed.length >= 2 && trimmed.first() == '\'' && trimmed.last() == '\'') {
            return trimmed.substring(1, trimmed.lastIndex).replace("''", "'")
        }
        if (trimmed.length >= 2 && trimmed.first() == '"' && trimmed.last() == '"') {
            return decodeDoubleQuotedYamlScalar(trimmed.substring(1, trimmed.lastIndex))
        }
        if (trimmed.startsWith('"') || trimmed.startsWith('\'')) return null
        return trimmed
    }

    private fun decodeDoubleQuotedYamlScalar(value: String): String? {
        val output = StringBuilder(value.length)
        var index = 0
        while (index < value.length) {
            val char = value[index]
            if (char != '\\') {
                output.append(char)
                index += 1
                continue
            }
            if (index == value.lastIndex) return null
            when (value[index + 1]) {
                '"' -> output.append('"')
                '\\' -> output.append('\\')
                '/' -> output.append('/')
                'b' -> output.append('\b')
                'f' -> output.append('\u000C')
                'n' -> output.append('\n')
                'r' -> output.append('\r')
                't' -> output.append('\t')
                'u' -> {
                    val high = unicodeEscape(value, index + 2, 4) ?: return null
                    if (high in HIGH_SURROGATE_RANGE) {
                        val lowEscapeIndex = index + 6
                        if (
                            lowEscapeIndex + 6 > value.length ||
                            value[lowEscapeIndex] != '\\' ||
                            value[lowEscapeIndex + 1] != 'u'
                        ) {
                            return null
                        }
                        val low = unicodeEscape(value, lowEscapeIndex + 2, 4) ?: return null
                        if (low !in LOW_SURROGATE_RANGE) return null
                        output.append(high.toChar()).append(low.toChar())
                        index += 12
                        continue
                    }
                    if (high in LOW_SURROGATE_RANGE) return null
                    output.append(high.toChar())
                    index += 6
                    continue
                }
                'U' -> {
                    val codePoint = unicodeEscape(value, index + 2, 8) ?: return null
                    if (codePoint > MAX_UNICODE_CODE_POINT || codePoint in SURROGATE_RANGE) return null
                    output.appendCodePoint(codePoint)
                    index += 10
                    continue
                }
                else -> return null
            }
            index += 2
        }
        return output.toString()
    }

    private fun unicodeEscape(value: String, start: Int, length: Int): Int? {
        val end = start + length
        if (end > value.length) return null
        return value.substring(start, end).toIntOrNull(16)
    }

    private fun yamlSingleQuoted(value: String): String = "'${value.replace("'", "''")}'"

    private fun nameTypeCounts(values: List<Pair<String, String>>): Map<Pair<String, String>, Int> =
        values.groupingBy { it }.eachCount()

    private fun fieldName(line: String): String =
        line.trimStart().substringBefore(':').trim().removeSurrounding("\"").removeSurrounding("'")

    private fun topLevelKey(line: String): String? {
        if (line.isBlank() || line.first().isWhitespace() || line.trimStart().startsWith("#")) return null
        val index = line.indexOf(':')
        if (index <= 0) return null
        return line.substring(0, index).trim().takeIf { it.isNotBlank() }
    }

    private fun indentation(line: String): Int =
        line.indexOfFirst { !it.isWhitespace() }.takeIf { it >= 0 } ?: line.length

    private fun result(
        yaml: String,
        rootName: String? = null,
        targetName: String? = null,
        reason: String,
    ) = MihomoAutomaticRoutingBridgeResult(
        yaml = yaml,
        applied = false,
        rootName = rootName,
        targetName = targetName,
        reason = reason,
    )

    private const val URL_TEST_TYPE = "urltest"
    private const val MAX_GROUP_DEPTH = 8
    private const val MAX_UNICODE_CODE_POINT = 0x10FFFF
    private val HIGH_SURROGATE_RANGE = 0xD800..0xDBFF
    private val LOW_SURROGATE_RANGE = 0xDC00..0xDFFF
    private val SURROGATE_RANGE = 0xD800..0xDFFF
}

object MihomoFrontingPatcher {
    fun patchProxyServers(
        rawYaml: String,
        serverOverrideIp: String?,
        serverOverridePort: Int? = null,
    ): String {
        val override = serverOverrideIp?.trim()?.takeIf { it.isNotBlank() } ?: return rawYaml
        val normalized = rawYaml.replace("\r\n", "\n").replace('\r', '\n')
        val output = mutableListOf<String>()
        var inProxies = false
        var currentProxy = mutableListOf<String>()

        fun flushProxy() {
            if (currentProxy.isEmpty()) return
            output += patchProxyBlock(currentProxy, override, serverOverridePort)
            currentProxy = mutableListOf()
        }

        normalized.split('\n').forEach { line ->
            val topLevelKey = topLevelKey(line)
            if (topLevelKey != null) {
                if (inProxies) flushProxy()
                inProxies = topLevelKey == "proxies"
                output += line
                return@forEach
            }

            if (!inProxies) {
                output += line
                return@forEach
            }

            val indent = indentation(line)
            val content = line.trimStart()
            if (indent == 2 && content.startsWith("- ")) {
                flushProxy()
                currentProxy += line
                return@forEach
            }

            if (currentProxy.isNotEmpty()) {
                currentProxy += line
            } else {
                output += line
            }
        }
        if (inProxies) flushProxy()

        return output.joinToString("\n")
    }

    private fun patchProxyBlock(lines: List<String>, override: String, portOverride: Int?): List<String> {
        return lines.map { line ->
            when {
                isProxyField(line, "server") -> replaceYamlValue(line, "server", override)
                portOverride != null && isProxyField(line, "port") ->
                    replaceYamlValue(line, "port", portOverride.toString())
                isInlineProxyMap(line) -> replaceInlineServerAndPort(line, override, portOverride)
                else -> line
            }
        }
    }

    private fun isProxyField(line: String, key: String): Boolean {
        val indent = indentation(line)
        if (indent != 4) return false
        val content = line.trimStart()
        return content.startsWith("$key:")
    }

    private fun replaceYamlValue(line: String, key: String, value: String): String {
        val indent = line.takeWhile(Char::isWhitespace)
        val comment = inlineComment(line.substringAfter(":", ""))
        return "$indent$key: $value$comment"
    }

    private fun inlineComment(value: String): String {
        val index = value.indexOf(" #")
        return if (index >= 0) value.substring(index) else ""
    }

    private fun isInlineProxyMap(line: String): Boolean {
        val content = line.trimStart()
        return content.startsWith("- {") && content.contains("server:")
    }

    private fun replaceInlineServerAndPort(line: String, value: String, portOverride: Int?): String {
        val patched = line.replace(Regex("""server:\s*([^,}]+)"""), "server: $value")
        return if (portOverride == null) patched else {
            patched.replace(Regex("""port:\s*([^,}]+)"""), "port: $portOverride")
        }
    }

    private fun topLevelKey(line: String): String? {
        if (line.isBlank() || line.first().isWhitespace() || line.trimStart().startsWith("#")) return null
        val index = line.indexOf(':')
        if (index <= 0) return null
        return line.substring(0, index).trim().takeIf { it.isNotBlank() }
    }

    private fun indentation(line: String): Int {
        return line.indexOfFirst { !it.isWhitespace() }.takeIf { it >= 0 } ?: line.length
    }
}

object MihomoConnectionOptionsPatcher {
    fun patch(rawYaml: String, options: MihomoConnectionOptions): String {
        if (!options.amneziaNoiseEnabled) return rawYaml
        val output = mutableListOf<String>()
        var inProxies = false
        var currentProxy = mutableListOf<String>()

        fun flushProxy() {
            if (currentProxy.isEmpty()) return
            output += patchProxyBlock(currentProxy, options)
            currentProxy = mutableListOf()
        }

        rawYaml.replace("\r\n", "\n").replace('\r', '\n').split('\n').forEach { line ->
            val topLevelKey = topLevelKey(line)
            if (topLevelKey != null) {
                if (inProxies) flushProxy()
                inProxies = topLevelKey == "proxies"
                output += line
                return@forEach
            }
            if (!inProxies) {
                output += line
                return@forEach
            }
            if (indentation(line) == 2 && line.trimStart().startsWith("- ")) {
                flushProxy()
                currentProxy += line
            } else if (currentProxy.isNotEmpty()) {
                currentProxy += line
            } else {
                output += line
            }
        }
        if (inProxies) flushProxy()
        return output.joinToString("\n")
    }

    private fun patchProxyBlock(
        lines: List<String>,
        options: MihomoConnectionOptions,
    ): List<String> {
        val type = proxyFieldValue(lines, "type").orEmpty()
        var patched = lines
        if (options.amneziaNoiseEnabled && type.equals("wireguard", true)) {
            val noise = options.amneziaNoise
            val amneziaFields = linkedMapOf(
                "jc" to noise.count.toString(),
                "jmin" to noise.minSize.toString(),
                "jmax" to noise.maxSize.toString(),
            )
            noise.version?.let { amneziaFields["version"] = it.toString() }
            listOf(
                "header-protection-key" to noise.headerProtectionKey,
                "content-padding-addition" to noise.contentPaddingAddition,
                "rekey-after-time" to noise.rekeyAfterTime,
                "rekey-timeout" to noise.rekeyTimeout,
                "reject-after-time" to noise.rejectAfterTime,
                "keepalive-timeout" to noise.keepaliveTimeout,
                "max-handshake-attempts" to noise.maxHandshakeAttempts,
            ).forEach { (field, value) ->
                if (value.isNotBlank()) amneziaFields[field] = yamlSingleQuoted(value)
            }
            noise.randomTrailers?.let { amneziaFields["random-trailers"] = it.toString() }
            noise.disableCookies?.let { amneziaFields["disable-cookies"] = it.toString() }
            patched = upsertNestedOptions(
                patched,
                "amnezia-wg-option",
                amneziaFields,
            )
            noise.fakeTtl?.let { ttl ->
                patched = upsertNestedOptions(
                    patched,
                    "wireguard-dpi-option",
                    linkedMapOf(
                        "fake-count" to noise.count.toString(),
                        "fake-min-size" to noise.minSize.toString(),
                        "fake-max-size" to noise.maxSize.toString(),
                        "fake-ttl" to ttl.toString(),
                    ),
                )
            }
            val ipStackFields = linkedMapOf<String, String>()
            noise.ipStackMode?.let { ipStackFields["mode"] = it }
            noise.congestionController?.let { ipStackFields["congestion-controller"] = it }
            if (ipStackFields.isNotEmpty()) {
                patched = upsertNestedOptions(patched, "ip-stack", ipStackFields)
            }
        }
        return patched
    }

    private fun upsertNestedOptions(
        lines: List<String>,
        key: String,
        fields: Map<String, String>,
    ): List<String> {
        if (lines.size == 1 && lines.single().trimStart().startsWith("- {")) {
            return listOf(upsertInlineMap(lines.single(), key, fields))
        }
        val start = lines.indexOfFirst { indentation(it) == 4 && fieldName(it) == key }
        if (start < 0) {
            return lines + "    $key:" + fields.map { (field, value) -> "      $field: $value" }
        }
        if (lines[start].substringAfter(':').trim().startsWith("{")) {
            return lines.toMutableList().also { it[start] = upsertInlineMap(it[start], key, fields) }
        }

        val patched = lines.toMutableList()
        var end = (start + 1 until patched.size)
            .firstOrNull { indentation(patched[it]) <= 4 && patched[it].isNotBlank() }
            ?: patched.size
        fields.forEach { (field, value) ->
            val index = (start + 1 until end).firstOrNull {
                indentation(patched[it]) == 6 && fieldName(patched[it]) == field
            }
            if (index == null) {
                patched.add(end, "      $field: $value")
                end += 1
            } else {
                patched[index] = "      $field: $value"
            }
        }
        return patched
    }

    private fun upsertInlineMap(line: String, key: String, fields: Map<String, String>): String {
        val keyPattern = Regex.escape(key)
        val nestedMap = Regex("""(['\"]?$keyPattern['\"]?\s*:\s*)\{([^}]*)}""")
        val match = nestedMap.find(line)
        if (match != null) {
            val body = patchInlineFields(match.groupValues[2], fields)
            return line.replaceRange(match.range, "${match.groupValues[1]}{$body}")
        }
        val close = line.lastIndexOf('}')
        if (close < 0) return line
        val separator = if (line.substring(0, close).trimEnd().endsWith('{')) "" else ", "
        val body = fields.entries.joinToString(", ") { (field, value) -> "$field: $value" }
        return line.substring(0, close) + "$separator$key: {$body}" + line.substring(close)
    }

    private fun patchInlineFields(body: String, fields: Map<String, String>): String {
        var patched = body.trim()
        fields.forEach { (field, value) ->
            val fieldPattern = Regex("""((?:^|,\s*)['\"]?${Regex.escape(field)}['\"]?\s*:\s*)([^,}]+)""")
            val match = fieldPattern.find(patched)
            patched = if (match == null) {
                patched + if (patched.isBlank()) "$field: $value" else ", $field: $value"
            } else {
                val valueRange = match.groups[2]?.range ?: return@forEach
                patched.replaceRange(valueRange, value)
            }
        }
        return patched
    }

    private fun proxyFieldValue(lines: List<String>, key: String): String? {
        lines.firstOrNull { indentation(it) == 4 && fieldName(it) == key }?.let { line ->
            return yamlScalar(line.substringAfter(':'))
        }
        val inline = lines.singleOrNull()?.trimStart()?.takeIf { it.startsWith("- {") } ?: return null
        return Regex("""(?:^|[,{]\s*)['\"]?${Regex.escape(key)}['\"]?\s*:\s*([^,}]+)""")
            .find(inline)
            ?.groupValues
            ?.get(1)
            ?.let(::yamlScalar)
    }

    private fun fieldName(line: String): String =
        line.trimStart().substringBefore(':').trim().removeSurrounding("\"").removeSurrounding("'")

    private fun yamlScalar(value: String): String =
        value.substringBefore(" #").trim().removeSurrounding("\"").removeSurrounding("'")

    private fun yamlSingleQuoted(value: String): String = "'${value.replace("'", "''")}'"

    private fun topLevelKey(line: String): String? {
        if (line.isBlank() || line.first().isWhitespace() || line.trimStart().startsWith("#")) return null
        return line.substringBefore(':').trim().takeIf { ':' in line && it.isNotBlank() }
    }

    private fun indentation(line: String): Int =
        line.indexOfFirst { !it.isWhitespace() }.takeIf { it >= 0 } ?: line.length
}

object MihomoDpiBypassPatcher {
    fun patch(
        rawYaml: String,
        enabled: Boolean,
        proxyPort: Int = DpiBypassDefaults.FALLBACK_PROXY_PORT,
    ): String {
        if (!enabled) return rawYaml
        val normalized = rawYaml.replace("\r\n", "\n").replace('\r', '\n')
        val output = mutableListOf<String>()
        var inProxies = false
        var sawProxies = false
        var sawDpiProxy = false
        var currentProxy = mutableListOf<String>()

        fun flushProxy() {
            if (currentProxy.isEmpty()) return
            if (proxyName(currentProxy) == DpiBypassDefaults.PROXY_NAME) {
                sawDpiProxy = true
                output += dpiProxyBlock(proxyPort)
            } else {
                output += withDialerProxy(currentProxy)
            }
            currentProxy = mutableListOf()
        }

        fun appendDpiProxy() {
            if (sawDpiProxy) return
            output += dpiProxyBlock(proxyPort)
            sawDpiProxy = true
        }

        normalized.split('\n').forEach { line ->
            val topLevelKey = topLevelKey(line)
            if (topLevelKey != null) {
                if (inProxies) {
                    flushProxy()
                    appendDpiProxy()
                }
                inProxies = topLevelKey == "proxies"
                sawProxies = sawProxies || inProxies
                output += line
                return@forEach
            }

            if (!inProxies) {
                output += line
                return@forEach
            }

            val content = line.trimStart()
            if (indentation(line) == 2 && content.startsWith("- ")) {
                flushProxy()
                currentProxy += line
                return@forEach
            }

            if (currentProxy.isNotEmpty()) {
                currentProxy += line
            } else {
                output += line
            }
        }
        if (inProxies) {
            flushProxy()
            appendDpiProxy()
        }
        if (!sawProxies) {
            if (output.isNotEmpty() && output.last().isNotBlank()) output += ""
            output += "proxies:"
            output += dpiProxyBlock(proxyPort)
        }

        return output.joinToString("\n")
    }

    private fun withDialerProxy(lines: List<String>): List<String> {
        if (lines.size == 1 && isInlineProxyMap(lines.single())) {
            return listOf(withInlineDialerProxy(lines.single()))
        }
        var replaced = false
        val patched = lines.map { line ->
            if (isDialerProxyField(line)) {
                replaced = true
                replaceYamlValue(line, DpiBypassDefaults.PROXY_NAME)
            } else {
                line
            }
        }.toMutableList()
        if (!replaced) {
            patched += "    dialer-proxy: ${yamlSingleQuoted(DpiBypassDefaults.PROXY_NAME)}"
        }
        return patched
    }

    private fun dpiProxyBlock(proxyPort: Int): List<String> {
        return listOf(
            "  - name: ${yamlSingleQuoted(DpiBypassDefaults.PROXY_NAME)}",
            "    type: socks5",
            "    server: ${DpiBypassDefaults.PROXY_HOST}",
            "    port: $proxyPort",
            "    udp: true",
        )
    }

    private fun proxyName(lines: List<String>): String? {
        lines.forEach { line ->
            val content = line.trimStart()
            val value = when {
                content.startsWith("- {") -> Regex("""name:\s*([^,}]+)""").find(content)?.groupValues?.get(1)
                content.startsWith("- name:") -> content.substringAfter("- name:")
                indentation(line) == 4 && content.startsWith("name:") -> content.substringAfter("name:")
                else -> null
            }
            value?.let { return decodeYamlScalar(it) }
        }
        return null
    }

    private fun isDialerProxyField(line: String): Boolean {
        return indentation(line) == 4 && line.trimStart().startsWith("dialer-proxy:")
    }

    private fun replaceYamlValue(line: String, value: String): String {
        val indent = line.takeWhile(Char::isWhitespace)
        val comment = inlineComment(line.substringAfter(":", ""))
        return "$indent" + "dialer-proxy: ${yamlSingleQuoted(value)}$comment"
    }

    private fun withInlineDialerProxy(line: String): String {
        val quoted = yamlSingleQuoted(DpiBypassDefaults.PROXY_NAME)
        if ("dialer-proxy:" in line) {
            return line.replace(Regex("""dialer-proxy:\s*([^,}]+)"""), "dialer-proxy: $quoted")
        }
        return line.replaceFirst(Regex("""\}\s*$"""), ", dialer-proxy: $quoted }")
    }

    private fun isInlineProxyMap(line: String): Boolean {
        return line.trimStart().startsWith("- {")
    }

    private fun inlineComment(value: String): String {
        val index = value.indexOf(" #")
        return if (index >= 0) value.substring(index) else ""
    }

    private fun decodeYamlScalar(value: String): String {
        val trimmed = value.trim().substringBefore(" #").trim()
        if (trimmed.length >= 2 && trimmed.first() == '\'' && trimmed.last() == '\'') {
            return trimmed.substring(1, trimmed.lastIndex).replace("''", "'")
        }
        if (trimmed.length >= 2 && trimmed.first() == '"' && trimmed.last() == '"') {
            return trimmed.substring(1, trimmed.lastIndex)
        }
        return trimmed
    }

    private fun yamlSingleQuoted(value: String): String {
        return "'${value.replace("'", "''")}'"
    }

    private fun topLevelKey(line: String): String? {
        if (line.isBlank() || line.first().isWhitespace() || line.trimStart().startsWith("#")) return null
        val index = line.indexOf(':')
        if (index <= 0) return null
        return line.substring(0, index).trim().takeIf { it.isNotBlank() }
    }

    private fun indentation(line: String): Int {
        return line.indexOfFirst { !it.isWhitespace() }.takeIf { it >= 0 } ?: line.length
    }
}

class MihomoControllerClient(
    @Suppress("UNUSED_PARAMETER") private val secret: String,
    @Suppress("UNUSED_PARAMETER") private val host: String = MihomoRuntimeDefaults.CONTROLLER_HOST,
    @Suppress("UNUSED_PARAMETER") private val port: Int = MihomoRuntimeDefaults.FALLBACK_CONTROL_PORT,
) {
    val endpoint: String
        get() = "core-actions"

    internal fun proxyTraffic(): EngineTrafficRate = EngineTrafficRate.parse(
        invokeAction("getTraffic", data = true).getString("data"),
    )

    fun getProxies(timeoutMs: Int = CORE_ACTION_TIMEOUT_MS): JSONObject {
        return invokeAction("getProxies", timeoutMs = timeoutMs)
            .optJSONObject("data")
            ?: throw IOException("Mihomo core getProxies returned no data")
    }

    fun activeProxyName(selectedName: String?): String? {
        return MihomoControllerProxies.activeProxyName(getProxies(), selectedName)
    }

    fun selectProxy(groupName: String, selectedName: String) {
        val message = invokeAction(
            method = "changeProxy",
            data = JSONObject()
                .put("group-name", groupName)
                .put("proxy-name", selectedName)
                .toString(),
        ).optString("data")
        if (message.isNotBlank()) {
            throw IOException("Mihomo core changeProxy failed: $message")
        }
    }

    fun clearProxySelection(groupName: String) {
        selectProxy(groupName, "")
    }

    fun delay(
        name: String,
        timeoutMs: Int = 5_000,
        url: String = MihomoRuntimeDefaults.DELAY_TEST_URL,
    ): Int? {
        val payload = invokeAction(
            method = "asyncTestDelay",
            data = JSONObject()
                .put("proxy-name", name)
                .put("test-url", url)
                .put("timeout", timeoutMs)
                .toString(),
            timeoutMs = timeoutMs + CORE_ACTION_TIMEOUT_PADDING_MS,
        ).optString("data")
        return runCatching { JSONObject(payload).optInt("value", -1).takeIf { it >= 0 } }.getOrNull()
    }

    private fun invokeAction(
        method: String,
        data: Any? = null,
        timeoutMs: Int = CORE_ACTION_TIMEOUT_MS,
    ): JSONObject {
        val action = JSONObject()
            .put("id", "$method-${System.nanoTime()}")
            .put("method", method)
        if (data != null) {
            action.put("data", data)
        }

        val latch = CountDownLatch(1)
        var response: String? = null
        Core.invokeAction(action.toString()) { result ->
            response = result
            latch.countDown()
        }
        if (!latch.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS)) {
            throw IOException("Mihomo core action $method timed out")
        }
        val root = runCatching { JSONObject(response.orEmpty()) }
            .getOrElse { error -> throw IOException("Mihomo core action $method returned invalid JSON", error) }
        if (root.optInt("code", -1) != 0) {
            throw IOException("Mihomo core action $method failed: ${root.opt("data")}")
        }
        return root
    }

    private companion object {
        const val CORE_ACTION_TIMEOUT_MS = 5_000
        const val CORE_ACTION_TIMEOUT_PADDING_MS = 1_000
    }
}

data class MihomoAdaptiveSelectionPlan(
    val groupName: String,
    val groupType: String,
    val selections: List<MihomoGroupSelection>,
)

internal data class MihomoQuickFastestCandidate(
    val name: String,
    val delayMs: Int,
    val order: Int,
)

internal data class MihomoQuickFastestPlan(
    val groupName: String,
    val originalFixed: String,
    val candidates: List<MihomoQuickFastestCandidate>,
)

internal data class MihomoQuickFastestMeasurement(
    val candidate: MihomoQuickFastestCandidate,
    val speedKbps: Int,
)

internal object MihomoQuickFastestPolicy {
    fun hasRequiredCapabilities(response: JSONObject, groupName: String): Boolean {
        val group = response.optJSONObject("proxies")?.optJSONObject(groupName) ?: return false
        return group.optString("type").lowercase().filter(Char::isLetterOrDigit) == "urltest" &&
            group.opt("fixed") is String &&
            group.opt("all") is JSONArray &&
            (group.opt("testUrl") as? String)?.isNotBlank() == true
    }

    fun plan(
        response: JSONObject,
        groupName: String,
        availableProfileNames: Set<String>,
    ): MihomoQuickFastestPlan? {
        val proxies = response.optJSONObject("proxies") ?: return null
        val group = proxies.optJSONObject(groupName) ?: return null
        if (!hasRequiredCapabilities(response, groupName)) return null
        val fixed = group.getString("fixed")
        val members = group.getJSONArray("all")
        val testUrl = group.getString("testUrl")
        val seen = mutableSetOf<String>()
        val candidates = buildList {
            for (index in 0 until members.length()) {
                val name = members.optString(index).takeIf(String::isNotBlank) ?: continue
                if (!seen.add(name) || name !in availableProfileNames) continue
                val proxy = proxies.optJSONObject(name) ?: continue
                if (proxy.optJSONArray("all") != null) continue
                val health = proxy.optJSONObject("extra")?.optJSONObject(testUrl) ?: continue
                if (!health.optBoolean("alive", false)) continue
                val history = health.optJSONArray("history") ?: continue
                val delay = history.optJSONObject(history.length() - 1)
                    ?.optInt("delay", -1)
                    ?.takeIf { it > 0 }
                    ?: continue
                add(MihomoQuickFastestCandidate(name, delay, index))
            }
        }.sortedWith(compareBy<MihomoQuickFastestCandidate> { it.delayMs }.thenBy { it.order })
            .take(MAX_CANDIDATES)
        if (candidates.size < MIN_MEASUREMENTS) return null
        return MihomoQuickFastestPlan(groupName, fixed, candidates)
    }

    fun winner(measurements: List<MihomoQuickFastestMeasurement>): MihomoQuickFastestMeasurement? {
        val valid = measurements.filter { it.speedKbps > 0 }
        if (valid.size < MIN_MEASUREMENTS) return null
        val maximumSpeed = valid.maxOf(MihomoQuickFastestMeasurement::speedKbps)
        return valid.asSequence()
            .filter { it.speedKbps.toLong() * 100L >= maximumSpeed.toLong() * SPEED_BAND_PERCENT }
            .minWithOrNull(
                compareBy<MihomoQuickFastestMeasurement> { it.candidate.delayMs }
                    .thenByDescending { it.speedKbps }
                    .thenBy { it.candidate.order },
            )
    }

    fun isPinnedActive(
        response: JSONObject,
        rootName: String,
        groupName: String,
        selectedName: String,
    ): Boolean {
        val group = response.optJSONObject("proxies")?.optJSONObject(groupName) ?: return false
        return group.opt("fixed") == selectedName &&
            group.optString("now") == selectedName &&
            MihomoControllerProxies.isActiveThrough(response, rootName, groupName) &&
            MihomoControllerProxies.activeProxyName(response, rootName) == selectedName
    }

    private const val MAX_CANDIDATES = 3
    private const val MIN_MEASUREMENTS = 2
    private const val SPEED_BAND_PERCENT = 80L
}

object MihomoControllerProxies {
    fun hasResolvedActiveRoute(response: JSONObject, rootName: String): Boolean {
        val proxies = response.optJSONObject("proxies") ?: return false
        var name = rootName.takeIf(String::isNotBlank) ?: return false
        val seen = mutableSetOf<String>()
        repeat(MAX_GROUP_DEPTH) { depth ->
            if (!seen.add(name)) return false
            val item = proxies.optJSONObject(name) ?: return false
            val type = normalizeType(item.optString("type"))
            val members = item.optJSONArray("all")
            if (type == "loadbalance") {
                return members != null &&
                    (0 until members.length()).any { proxies.optJSONObject(members.optString(it)) != null }
            }
            val now = item.optString("now").takeIf(String::isNotBlank)
            if (now == null) {
                return depth > 0 && type.isNotBlank() && members == null
            }
            name = now
        }
        return false
    }

    fun activeProxyName(response: JSONObject, selectedName: String?): String? {
        val proxies = response.optJSONObject("proxies") ?: return selectedName
        var name = selectedName?.takeIf(String::isNotBlank) ?: return null
        val seen = mutableSetOf<String>()
        repeat(MAX_GROUP_DEPTH) {
            if (!seen.add(name)) return name
            val item = proxies.optJSONObject(name) ?: return name
            val now = item.optString("now").takeIf(String::isNotBlank) ?: return name
            name = now
        }
        return name
    }

    fun isActiveThrough(response: JSONObject, rootName: String, targetName: String): Boolean {
        val proxies = response.optJSONObject("proxies") ?: return false
        var name = rootName.takeIf(String::isNotBlank) ?: return false
        val target = targetName.takeIf(String::isNotBlank) ?: return false
        val seen = mutableSetOf<String>()
        repeat(MAX_GROUP_DEPTH) {
            val item = proxies.optJSONObject(name) ?: return false
            if (name == target) return true
            if (!seen.add(name)) return false
            val now = item.optString("now").takeIf(String::isNotBlank) ?: return false
            name = now
        }
        return name == target && proxies.optJSONObject(name) != null
    }

    fun selectorPath(
        response: JSONObject,
        targetName: String,
        preferredRoots: List<String> = emptyList(),
    ): List<MihomoGroupSelection> {
        val proxies = response.optJSONObject("proxies") ?: return emptyList()
        val selectorNames = proxies.keys().asSequence()
            .filter { name ->
                proxies.optJSONObject(name)
                    ?.optString("type")
                    .equals("Selector", ignoreCase = true)
            }
            .toList()
        val roots = preferredRoots
            .takeIf(List<String>::isNotEmpty)
            ?.filter { it in selectorNames }
            ?.distinct()
            ?: selectorNames
        roots.forEach { root ->
            val path = selectorPathFrom(
                proxies = proxies,
                currentName = root,
                targetName = targetName,
                visited = emptySet(),
            ) ?: return@forEach
            return path.zipWithNext()
                .map { (selector, selected) -> MihomoGroupSelection(selector, selected) }
                .reversed()
        }
        return emptyList()
    }

    fun selectableTargetNames(
        response: JSONObject,
        targetNames: Collection<String>,
        preferredRoots: List<String> = emptyList(),
    ): Set<String> {
        val proxies = response.optJSONObject("proxies") ?: return emptySet()
        val roots = selectorRoots(proxies, preferredRoots)
        if (roots.isEmpty()) return emptySet()
        val reachable = reachableSelectorPaths(proxies, roots).keys
        return targetNames.filterTo(linkedSetOf()) { it in reachable }
    }

    fun rootScopedAdaptivePlan(
        response: JSONObject,
        rootName: String,
        preferredGroupNames: List<String> = emptyList(),
        excludedGroupNames: Set<String> = emptySet(),
        excludedGroupTypes: Set<String> = emptySet(),
    ): MihomoAdaptiveSelectionPlan? {
        val proxies = response.optJSONObject("proxies") ?: return null
        val root = proxies.optJSONObject(rootName) ?: return null
        val rootType = root.optString("type")
        val normalizedExcludedTypes = excludedGroupTypes.mapTo(mutableSetOf(), ::normalizeType)
        if (adaptiveTypeRank(rootType) != null) {
            if (rootName in excludedGroupNames || normalizeType(rootType) in normalizedExcludedTypes) return null
            return MihomoAdaptiveSelectionPlan(
                groupName = rootName,
                groupType = rootType,
                selections = emptyList(),
            )
        }
        if (!rootType.equals("Selector", ignoreCase = true)) return null

        val reachable = reachableSelectorPaths(proxies, listOf(rootName))
        val preferredIndexes = preferredGroupNames
            .distinct()
            .mapIndexed { index, name -> name to index }
            .toMap()
        val directIndexes = root.optJSONArray("all")
            ?.let { members ->
                buildMap {
                    for (index in 0 until members.length()) {
                        val name = members.optString(index).takeIf(String::isNotBlank) ?: continue
                        putIfAbsent(name, index)
                    }
                }
            }
            .orEmpty()
        val candidates = reachable.entries.mapIndexedNotNull { discoveryIndex, entry ->
            val name = entry.key
            if (name in excludedGroupNames) return@mapIndexedNotNull null
            val item = proxies.optJSONObject(name) ?: return@mapIndexedNotNull null
            val type = item.optString("type")
            if (normalizeType(type) in normalizedExcludedTypes) return@mapIndexedNotNull null
            val typeRank = adaptiveTypeRank(type) ?: return@mapIndexedNotNull null
            val preferredIndex = preferredIndexes[name]
            val directIndex = directIndexes[name]
            if (preferredIndex == null && directIndex == null) return@mapIndexedNotNull null
            AdaptiveCandidate(
                name = name,
                type = type,
                typeRank = typeRank,
                path = entry.value,
                preferredIndex = preferredIndex ?: Int.MAX_VALUE,
                directIndex = directIndex ?: Int.MAX_VALUE,
                discoveryIndex = discoveryIndex,
            )
        }
        val selected = candidates.minWithOrNull(
            compareBy<AdaptiveCandidate> { it.typeRank }
                .thenBy { it.preferredIndex }
                .thenBy { it.directIndex }
                .thenBy { it.discoveryIndex },
        ) ?: return null
        return MihomoAdaptiveSelectionPlan(
            groupName = selected.name,
            groupType = selected.type,
            selections = selected.path.zipWithNext()
                .map { (selector, target) -> MihomoGroupSelection(selector, target) }
                .reversed(),
        )
    }

    fun currentSelections(
        response: JSONObject,
        path: List<MihomoGroupSelection>,
    ): List<MihomoGroupSelection> {
        val proxies = response.optJSONObject("proxies") ?: return emptyList()
        return path.mapNotNull { selection ->
            proxies.optJSONObject(selection.selectorGroup)
                ?.optString("now")
                ?.takeIf(String::isNotBlank)
                ?.let { MihomoGroupSelection(selection.selectorGroup, it) }
        }
    }

    private fun selectorPathFrom(
        proxies: JSONObject,
        currentName: String,
        targetName: String,
        visited: Set<String>,
    ): List<String>? {
        if (currentName == targetName) return listOf(targetName)
        if (currentName in visited || visited.size >= MAX_GROUP_DEPTH) return null
        val item = proxies.optJSONObject(currentName) ?: return null
        if (!item.optString("type").equals("Selector", ignoreCase = true)) return null
        val members = item.optJSONArray("all") ?: return null
        for (index in 0 until members.length()) {
            val member = members.optString(index).takeIf(String::isNotBlank) ?: continue
            val childPath = selectorPathFrom(
                proxies = proxies,
                currentName = member,
                targetName = targetName,
                visited = visited + currentName,
            ) ?: continue
            return listOf(currentName) + childPath
        }
        return null
    }

    private data class AdaptiveCandidate(
        val name: String,
        val type: String,
        val typeRank: Int,
        val path: List<String>,
        val preferredIndex: Int,
        val directIndex: Int,
        val discoveryIndex: Int,
    )

    private data class PendingSelector(
        val name: String,
        val path: List<String>,
        val depth: Int,
    )

    private fun selectorRoots(proxies: JSONObject, preferredRoots: List<String>): List<String> {
        val selectorNames = proxies.keys().asSequence()
            .filter { name ->
                proxies.optJSONObject(name)
                    ?.optString("type")
                    .equals("Selector", ignoreCase = true)
            }
            .toList()
        return preferredRoots
            .takeIf(List<String>::isNotEmpty)
            ?.filter { it in selectorNames }
            ?.distinct()
            ?: selectorNames
    }

    private fun reachableSelectorPaths(
        proxies: JSONObject,
        roots: List<String>,
    ): LinkedHashMap<String, List<String>> {
        val reachable = linkedMapOf<String, List<String>>()
        val pending = roots.mapTo(mutableListOf()) { root ->
            PendingSelector(name = root, path = listOf(root), depth = 0)
        }
        val visitedSelectors = mutableSetOf<String>()
        var pendingIndex = 0
        while (pendingIndex < pending.size) {
            val current = pending[pendingIndex++]
            if (!visitedSelectors.add(current.name) || current.depth >= MAX_GROUP_DEPTH) continue
            val item = proxies.optJSONObject(current.name) ?: continue
            if (!item.optString("type").equals("Selector", ignoreCase = true)) continue
            val members = item.optJSONArray("all") ?: continue
            for (memberIndex in 0 until members.length()) {
                val member = members.optString(memberIndex).takeIf(String::isNotBlank) ?: continue
                val path = current.path + member
                reachable.putIfAbsent(member, path)
                if (
                    proxies.optJSONObject(member)
                        ?.optString("type")
                        .equals("Selector", ignoreCase = true)
                ) {
                    pending += PendingSelector(member, path, current.depth + 1)
                }
            }
        }
        return reachable
    }

    private fun adaptiveTypeRank(type: String): Int? = when (normalizeType(type)) {
        "urltest" -> 0
        "fallback" -> 1
        "loadbalance" -> 2
        else -> null
    }

    private fun normalizeType(type: String): String = type.lowercase().filter(Char::isLetterOrDigit)

    private const val MAX_GROUP_DEPTH = 8
}

internal object MihomoRuntimeHealthDeadlinePolicy {
    fun deadlineMs(startedAtMs: Long, totalTimeoutMs: Long): Long =
        startedAtMs + totalTimeoutMs.coerceAtLeast(0L)

    fun probeTimeoutMs(
        deadlineMs: Long,
        nowMs: Long,
        remainingUrlCount: Int,
    ): Int? {
        if (remainingUrlCount <= 0 || nowMs >= deadlineMs) return null
        return ((deadlineMs - nowMs) / (remainingUrlCount * HTTP_PHASES_PER_URL))
            .coerceAtMost(MAX_HTTP_PHASE_TIMEOUT_MS.toLong())
            .toInt()
            .takeIf { it > 0 }
    }

    fun pollDelayMs(
        deadlineMs: Long,
        nowMs: Long,
        requestedMs: Long = MAX_POLL_DELAY_MS,
    ): Long = (deadlineMs - nowMs)
        .coerceAtLeast(0L)
        .coerceAtMost(requestedMs.coerceIn(0L, MAX_POLL_DELAY_MS))

    private const val HTTP_PHASES_PER_URL = 2L
    private const val MAX_HTTP_PHASE_TIMEOUT_MS = 3_000
    private const val MAX_POLL_DELAY_MS = 500L
}

object MihomoRuntimeHealth {
    fun isMixedProxyReachable(timeoutMs: Int = 500): Boolean = runCatching {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(MihomoRuntimeDefaults.CONTROLLER_HOST, MihomoRuntimeDefaults.MIXED_PORT),
                timeoutMs.coerceAtLeast(1),
            )
        }
    }.isSuccess

    fun httpStatusThroughMixedProxy(
        url: String = MihomoRuntimeDefaults.HEALTH_URL,
        timeoutMs: Int = 3_000,
    ): Int {
        val proxy = Proxy(
            Proxy.Type.HTTP,
            InetSocketAddress(MihomoRuntimeDefaults.CONTROLLER_HOST, MihomoRuntimeDefaults.MIXED_PORT),
        )
        return httpStatus(url, proxy, timeoutMs)
    }

    fun httpStatusThroughSocksProxy(
        port: Int,
        url: String = MihomoRuntimeDefaults.HEALTH_URL,
        timeoutMs: Int = 3_000,
    ): Int {
        val proxy = Proxy(
            Proxy.Type.SOCKS,
            InetSocketAddress(DpiBypassDefaults.PROXY_HOST, port),
        )
        return httpStatus(url, proxy, timeoutMs)
    }

    fun egressCountryCodeThroughMixedProxy(
        url: String = MihomoRuntimeDefaults.EGRESS_TRACE_URL,
        timeoutMs: Int = 2_000,
    ): String? {
        val proxy = Proxy(
            Proxy.Type.HTTP,
            InetSocketAddress(MihomoRuntimeDefaults.CONTROLLER_HOST, MihomoRuntimeDefaults.MIXED_PORT),
        )
        val connection = URL(url).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = timeoutMs
        connection.readTimeout = timeoutMs
        connection.instanceFollowRedirects = false
        return connection.use {
            if (responseCode !in 200..299) return@use null
            countryCodeFromTrace(inputStream.bufferedReader().use { it.readText() })
        }
    }

    suspend fun downloadSpeedKbpsThroughMixedProxy(
        downloadBytes: Long = MihomoRuntimeDefaults.SPEED_TEST_BYTES,
        timeoutMs: Int = 10_000,
        onResponseReady: () -> Unit = {},
    ): Int? {
        val targetBytes = downloadBytes.coerceAtLeast(1L)
        val proxy = Proxy(
            Proxy.Type.HTTP,
            InetSocketAddress(MihomoRuntimeDefaults.CONTROLLER_HOST, MihomoRuntimeDefaults.MIXED_PORT),
        )
        val connection = URL(
            "${MihomoRuntimeDefaults.SPEED_TEST_URL_PREFIX}$targetBytes",
        ).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = timeoutMs
        connection.readTimeout = timeoutMs
        connection.instanceFollowRedirects = false
        connection.useCaches = false
        connection.setRequestProperty("Accept-Encoding", "identity")
        connection.setRequestProperty("Connection", "close")
        return measureDownloadSpeed(connection, targetBytes, onResponseReady)
    }

    internal suspend fun measureDownloadSpeed(
        connection: HttpURLConnection,
        targetBytes: Long,
        onResponseReady: () -> Unit = {},
    ): Int? = coroutineScope {
        // Thread interruption alone does not reliably unblock an HTTP socket read.
        val disconnectOnCancel = launch(Dispatchers.IO, start = CoroutineStart.UNDISPATCHED) {
            try {
                awaitCancellation()
            } finally {
                connection.disconnect()
            }
        }
        try {
            runInterruptible(Dispatchers.IO) {
                if (connection.responseCode !in 200..299) return@runInterruptible null
                onResponseReady()
                val startedAtNanos = System.nanoTime()
                var bytesRead = 0L
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                connection.inputStream.use { input ->
                    while (bytesRead < targetBytes) {
                        val count = input.read(
                            buffer,
                            0,
                            minOf(buffer.size.toLong(), targetBytes - bytesRead).toInt(),
                        )
                        if (count <= 0) break
                        bytesRead += count
                    }
                }
                ConnectionSpeed.completeKbps(
                    bytes = bytesRead,
                    expectedBytes = targetBytes,
                    elapsedNanos = System.nanoTime() - startedAtNanos,
                )
            }
        } finally {
            withContext(NonCancellable) { disconnectOnCancel.cancelAndJoin() }
        }
    }

    fun countryCodeFromTrace(trace: String): String? {
        return trace.lineSequence()
            .firstOrNull { it.startsWith("loc=") }
            ?.substringAfter("=")
            ?.let(ConnectionLocationPolicy::normalizeCountryCode)
    }

    private fun httpStatus(url: String, proxy: Proxy, timeoutMs: Int): Int {
        val connection = URL(url).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = timeoutMs
        connection.readTimeout = timeoutMs
        connection.instanceFollowRedirects = false
        return connection.use {
            responseCode
        }
    }

    private inline fun <T> HttpURLConnection.use(block: HttpURLConnection.() -> T): T {
        return try {
            block()
        } finally {
            disconnect()
        }
    }
}

object ConnectionSpeed {
    fun completeKbps(bytes: Long, expectedBytes: Long, elapsedNanos: Long): Int? {
        if (bytes != expectedBytes) return null
        return kbps(bytes, elapsedNanos)
    }

    fun kbps(bytes: Long, elapsedNanos: Long): Int? {
        if (bytes <= 0L || elapsedNanos <= 0L) return null
        return (bytes * 8_000_000L / elapsedNanos)
            .coerceAtMost(Int.MAX_VALUE.toLong())
            .toInt()
            .takeIf { it > 0 }
    }
}
