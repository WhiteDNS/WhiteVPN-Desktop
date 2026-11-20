package com.whitedns.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.CancellationSignal
import android.os.Process
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.coroutines.resume

/** All lookups and sockets use this app's VPN network; cancellation closes pending socket probes. */
internal object EngineNetworkProbe {
    private val io = Executors.newFixedThreadPool(2) { task -> Thread(task, "native-vpn-probe").apply { isDaemon = true } }
    private val dns = Executors.newFixedThreadPool(2) { task -> Thread(task, "native-vpn-dns").apply { isDaemon = true } }

    fun ownedVpn(context: Context): Network? {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        return cm.allNetworks.firstOrNull { network -> cm.getNetworkCapabilities(network)?.let { caps ->
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && (Build.VERSION.SDK_INT < 30 || caps.ownerUid == Process.myUid())
        } == true }
    }
    suspend fun verifyDefaultVpn(context: Context, timeout: Long): Network =
        withTimeoutOrNull(timeout) {
            while (true) {
                val network = ownedVpn(context)
                if (network != null && probe(network)) return@withTimeoutOrNull network
                delay(500)
            }
            @Suppress("UNREACHABLE_CODE") error("VPN unavailable")
        } ?: error("VPN readiness timed out")

    suspend fun awaitRelease(context: Context): Boolean = withTimeoutOrNull(30000) {
        while (ownedVpn(context) != null) delay(20)
        true
    } == true

    suspend fun probe(network: Network): Boolean {
        for (target in MihomoRuntimeDefaults.HEALTH_URLS) {
            val url = URL(target)
            val addresses = withTimeoutOrNull(4000) { resolve(network, url.host) }.orEmpty()
            for (address in addresses.sortedBy { if (it is Inet4Address) 0 else 1 }) {
                if (withTimeoutOrNull(4000) { https(network, address, url) } == true) return true
            }
        }
        return false
    }

    private suspend fun resolve(network: Network, host: String): List<InetAddress> = suspendCancellableCoroutine { continuation ->
        if (Build.VERSION.SDK_INT >= 29) {
            val cancellation = CancellationSignal()
            continuation.invokeOnCancellation { cancellation.cancel() }
            try {
                DnsResolver.getInstance().query(network, host, DnsResolver.FLAG_EMPTY, dns, cancellation,
                    object : DnsResolver.Callback<List<InetAddress>> {
                        override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                            if (continuation.isActive) continuation.resume(if (rcode == 0) answer else emptyList())
                        }
                        override fun onError(error: DnsResolver.DnsException) {
                            if (continuation.isActive) continuation.resume(emptyList())
                        }
                    })
            } catch (_: Exception) { if (continuation.isActive) continuation.resume(emptyList()) }
        } else {
            val task = dns.submit {
                val addresses = runCatching { network.getAllByName(host).toList() }.getOrDefault(emptyList())
                if (continuation.isActive) continuation.resume(addresses)
            }
            continuation.invokeOnCancellation { task.cancel(true) }
        }
    }

    private suspend fun https(network: Network, address: InetAddress, url: URL): Boolean = suspendCancellableCoroutine { continuation ->
        val owned = AtomicReference<Socket?>()
        val task = io.submit {
            var result = false
            try {
                val port = if (url.port > 0) url.port else 443
                val socket = network.socketFactory.createSocket()
                owned.set(socket)
                if (!continuation.isActive) return@submit
                socket.soTimeout = 4000
                socket.connect(InetSocketAddress(address, port), 4000)
                val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(socket, url.host, port, true) as SSLSocket
                owned.set(tls)
                if (!continuation.isActive) return@submit
                tls.soTimeout = 4000
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.startHandshake()
                tls.getOutputStream().apply {
                    write(("GET " + url.file.ifBlank { "/" } + " HTTP/1.1\r\nHost: " + url.host +
                        "\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)); flush()
                }
                val response = StringBuilder()
                val input = tls.getInputStream()
                while (response.length < 1024) {
                    val c = input.read(); if (c < 0 || c == 10) break; response.append(c.toChar())
                }
                result = response.toString().split(' ').getOrNull(1)?.toIntOrNull() in 200..299
            } catch (_: Exception) {
                result = false
            } finally {
                runCatching { owned.getAndSet(null)?.close() }
                if (continuation.isActive) continuation.resume(result)
            }
        }
        continuation.invokeOnCancellation { runCatching { owned.getAndSet(null)?.close() }; task.cancel(true) }
    }
}
