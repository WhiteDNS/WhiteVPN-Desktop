package com.whitedns.vpn

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.amnezia.awg.GoBackend
import org.amnezia.awg.config.Config
import org.amnezia.awg.config.InetEndpoint
import java.io.BufferedReader
import java.io.StringReader
import java.net.Inet4Address
import java.util.concurrent.atomic.AtomicBoolean

/** Parsing never resolves endpoints or includes raw parser errors in diagnostics. */
internal object AmneziaProfile {
    fun parse(raw: String): Config {
        val config = try { Config.parse(BufferedReader(StringReader(raw))) }
        catch (_: Exception) { throw IllegalArgumentException("Invalid AmneziaWG configuration") }
        val iface = config.getInterface()
        require(iface.addresses.isNotEmpty()) { "AmneziaWG needs an interface address" }
        require(iface.dnsServers.isNotEmpty()) { "AmneziaWG needs DNS in its configuration" }
        require(iface.includedApplications.isEmpty() && iface.excludedApplications.isEmpty()) {
            "Use WhiteVPN app selection instead of applications in the configuration"
        }
        require(iface.mtu.orElse(1280) in 1280..65535) { "Invalid AmneziaWG MTU" }
        require(config.peers.isNotEmpty() && config.peers.all {
            it.endpoint.isPresent && it.endpoint.get().port in 1..65535 && it.allowedIps.isNotEmpty()
        }) { "AmneziaWG needs peers with endpoints and allowed routes" }
        return config
    }
    /** Called before establishment, using physical-network DNS rather than a previous VPN. */
    fun resolvedUserspace(config: Config, resolve: (String) -> String): String = buildString {
        append(config.getInterface().toAwgUserspaceString())
        append("replace_peers=true\n")
        config.peers.forEach { peer ->
            val ep = peer.endpoint.get()
            val host = resolve(ep.host.removeSurrounding("[", "]"))
            val numeric = InetEndpoint.parse((if (':' in host) "[" + host + "]" else host) + ":" + ep.port)
            // Replace the endpoint before serialization to avoid a system DNS lookup after establishing the TUN.
            val resolvedPeer = org.amnezia.awg.config.Peer.Builder().setPublicKey(peer.publicKey)
                .addAllowedIps(peer.allowedIps).setEndpoint(numeric).apply {
                    peer.preSharedKey.ifPresent { setPreSharedKey(it) }
                    peer.persistentKeepalive.ifPresent { parsePersistentKeepalive(it) }
                }.build()
            append(resolvedPeer.toAwgUserspaceString())
        }
    }
    fun publicSummary(config: Config): String = "DNS: " + config.getInterface().dnsServers.joinToString { it.hostAddress.orEmpty() } +
        "\nMTU: " + config.getInterface().mtu.orElse(1280) + "\nAllowedIPs: " + config.peers.flatMap { it.allowedIps }.distinct().joinToString()
}

/** The app owns the TUN; the private worker owns the Go runtime and protected UDP sockets. */
internal class AmneziaEngineBackend(private val service: VpnService, private val profile: EngineProfile,
    private val configureTun: (VpnService.Builder) -> Unit) : AbstractEngineBackend() {
    private var remote: RemoteEngineBackend? = null
    private var tunnel: ParcelFileDescriptor? = null
    override val running get() = remote?.running == true
    override val traffic get() = remote?.traffic
    override suspend fun start() {
        DiagnosticLogger.info(service, "amnezia.start", "stage=profile")
        val config = AmneziaProfile.parse(profile.value("config"))
        val physical = service.getSystemService(ConnectivityManager::class.java).let { cm ->
            cm.allNetworks.firstOrNull { network -> cm.getNetworkCapabilities(network)?.let {
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            } == true }
        } ?: error("No underlying network")
        DiagnosticLogger.info(service, "amnezia.start", "stage=endpoints")
        val settings = withContext(Dispatchers.IO) {
            AmneziaProfile.resolvedUserspace(config) { host ->
                val addresses = physical.getAllByName(host)
                (addresses.firstOrNull { it is Inet4Address } ?: addresses.first()).hostAddress!!
            }
        }
        DiagnosticLogger.info(service, "amnezia.start", "stage=tun")
        val iface = config.getInterface()
        val builder = service.Builder().setSession(profile.name).setBlocking(true).setMtu(iface.mtu.orElse(1280))
        iface.addresses.forEach { builder.addAddress(it.address, it.mask) }
        config.peers.flatMap { it.allowedIps }.distinct().forEach { builder.addRoute(it.address, it.mask) }
        iface.dnsServers.forEach { builder.addDnsServer(it) }
        iface.dnsSearchDomains.forEach { builder.addSearchDomain(it) }
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        configureTun(builder)
        tunnel = builder.establish() ?: error("VPN permission was revoked")
        val child = RemoteEngineBackend(service, profile, true, service, tunnel, settings)
        remote = child
        DiagnosticLogger.info(service, "amnezia.start", "stage=worker")
        child.start()
        state.value = BackendEvent.Ready
    }
    override suspend fun stop(): Boolean {
        val confirmed = remote?.stop() ?: true
        if (confirmed) {
            remote = null
            tunnel?.close(); tunnel = null
            if (!EngineNetworkProbe.awaitRelease(service)) return false
            state.value = BackendEvent.Stopped
        }
        return confirmed
    }
}

/** UAPI containing keys stays in the worker; only numeric byte counters cross IPC. */
internal object AmneziaTrafficCounters {
    data class Counters(val upload: Long, val download: Long)
    fun parse(raw: String): Counters {
        var up = 0L; var down = 0L
        raw.lineSequence().forEach { line ->
            val key = line.substringBefore('=')
            if (key == "tx_bytes" || key == "rx_bytes") {
                val value = line.substringAfter('=').toLongOrNull()?.takeIf { it >= 0 } ?: return@forEach
                if (key == "tx_bytes") up = saturate(up, value) else down = saturate(down, value)
            }
        }
        return Counters(up, down)
    }
    private fun saturate(a: Long, b: Long) = if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
}

internal class AmneziaWorkerBackend(private val tunnel: ParcelFileDescriptor,
    private val settings: String, private val protector: GoBackend.SocketProtector) : AbstractEngineBackend() {
    @Volatile private var handle = -1
    private val consumed = AtomicBoolean(false)
    private var last: AmneziaTrafficCounters.Counters? = null
    private var lastTime = 0L
    override val running get() = handle >= 0
    override suspend fun start() = withContext(Dispatchers.IO) {
        System.loadLibrary("amneziawg")
        GoBackend.protector = protector
        val fd = tunnel.detachFd(); consumed.set(true)
        handle = GoBackend.awgTurnOn("whiteawg", fd, settings)
        check(handle >= 0) { "AmneziaWG startup failed" }
        state.value = BackendEvent.Ready
    }
    fun sample(): EngineTrafficRate? {
        val raw = GoBackend.awgGetConfig(handle) ?: return null
        val counters = AmneziaTrafficCounters.parse(raw)
        val now = SystemClock.elapsedRealtime()
        val before = last; val interval = now - lastTime
        last = counters; lastTime = now
        if (before == null || interval <= 0) return null
        fun rate(a: Long, b: Long) = ((a - b).coerceAtLeast(0).toDouble() * 1000 / interval).coerceAtMost(Long.MAX_VALUE.toDouble()).toLong()
        return EngineTrafficRate(rate(counters.upload, before.upload), rate(counters.download, before.download))
    }
    override suspend fun stop(): Boolean = withContext(Dispatchers.IO) {
        if (handle >= 0) { GoBackend.awgTurnOff(handle); handle = -1 }
        GoBackend.protector = null
        if (!consumed.get()) tunnel.close()
        state.value = BackendEvent.Stopped
        true
    }
}
