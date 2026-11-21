package com.whitedns.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Ikev2VpnProfile
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnManager
import android.net.VpnProfileState
import android.os.Build
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import android.security.KeyChain
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayInputStream
import java.net.URL
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection

/** Platform VPN ownership survives the VpnService and activity. */
internal object PlatformIkev2Controller {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val mutex = Mutex()
    private val generations = AtomicLong()
    private var monitor: Job? = null
    private var startupJob: Job? = null
    private var activeProfile: EngineProfile? = null
    private var startedAt = 0L
    @Volatile private var currentState: VpnState = VpnState.Stopped
    fun observedState(): VpnState = currentState
    @RequiresApi(30)
    suspend fun prepare(context: Context, profile: EngineProfile): Intent? = withContext(Dispatchers.IO) {
        check(profile.kind == EngineKind.IKEV2)
        EnginePreflight.validate(profile, EngineNativeAvailability.check(context, profile), true, false)
        val server = profile.value("server")
        // API 30's public profile builder validates the gateway's server identity.
        require(profile.value("remoteId", server) == server) { "This platform profile requires the remote identity to match the server" }
        val builder = Ikev2VpnProfile.Builder(server, profile.value("localId").ifBlank { profile.value("username").ifBlank { server } })
        val ca = profile.value("caCertPem").takeIf { it.isNotBlank() }?.let {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(it.toByteArray())) as X509Certificate
        }
        when (profile.value("authType", "eap_mschapv2")) {
            "psk" -> builder.setAuthPsk(profile.value("psk").toByteArray(Charsets.UTF_8))
            "certificate" -> {
                val alias = profile.value("userCertAlias")
                val cert = KeyChain.getCertificateChain(context, alias)?.firstOrNull() ?: error("Client certificate is unavailable")
                val key = KeyChain.getPrivateKey(context, alias) ?: error("Client key is unavailable")
                builder.setAuthDigitalSignature(cert, key, ca)
            }
            else -> builder.setAuthUsernamePassword(profile.value("username"), profile.value("password"), ca)
        }
        context.getSystemService(VpnManager::class.java).provisionVpnProfile(builder.build())
    }
    @RequiresApi(30)
    fun startPrepared(context: Context, profile: EngineProfile) {
        activeProfile = profile
        EngineProfileStore(context).rememberPlatformProfile(profile.id)
        context.startForegroundService(Intent(context, EnginePlatformService::class.java).setAction(Actions.CONNECT))
    }
    fun owns(context: Context): Boolean = activeProfile != null || EngineProfileStore(context).platformProfileId() != null
    fun dispatch(context: Context, action: String) {
        context.startForegroundService(Intent(context, EnginePlatformService::class.java).setAction(action))
    }
    @RequiresApi(30)
    suspend fun handle(service: EnginePlatformService, action: String) {
        if (action == Actions.DISCONNECT && VpnRuntimeStateStore.readAlwaysOn(service)) return
        if (action in listOf(Actions.DISCONNECT, Actions.RECONNECT, Actions.REFRESH)) startupJob?.cancelAndJoin()
        mutex.withLock {
        val job = currentCoroutineContext().job
        startupJob = job
        try {
        when (action) {
            Actions.DISCONNECT -> {
                if (VpnRuntimeStateStore.readAlwaysOn(service)) return@withLock
                release(service)
            }
            Actions.RECONNECT, Actions.REFRESH -> {
                if (!release(service, stopService = false)) return@withLock
                val profile = EngineProfileStore(service).selectedEngineId()?.let { EngineProfileStore(service).profile(it) }
                if (profile?.kind == EngineKind.IKEV2) {
                    if (prepare(service, profile) != null) {
                        publish(service, VpnState.Error("Open WhiteVPN to grant IKEv2 permission")); service.stopSelf()
                    } else { activeProfile = profile; connect(service) }
                }
                else { service.stopSelf(); RouteServiceDispatcher.dispatch(service, Actions.CONNECT) }
            }
            else -> {
                if (action != "restore" && currentState in listOf(VpnState.Started, VpnState.Stopping)) {
                    service.updateNotification(service.getString(if (currentState == VpnState.Started) R.string.notification_connected else R.string.engine_release_pending))
                } else connect(service, adopt = action == "restore")
            }
        }
        } catch (error: Throwable) {
            if (error is CancellationException) throw error
            if (!owns(service)) { publish(service, VpnState.Error("IKEv2 profile could not be started")); service.stopSelf() }
            else publish(service, VpnState.Stopping)
        } finally { if (startupJob === job) startupJob = null }
        }
    }
    @RequiresApi(30)
    private suspend fun connect(service: EnginePlatformService, adopt: Boolean = false) {
        val profile = activeProfile ?: EngineProfileStore(service).platformProfileId()?.let { EngineProfileStore(service).profile(it) }
            ?: error("No provisioned IKEv2 profile")
        activeProfile = profile
        EngineProfileStore(service).rememberPlatformProfile(profile.id)
        val token = generations.incrementAndGet()
        publish(service, VpnState.Starting)
        val manager = service.getSystemService(VpnManager::class.java)
        try {
            if (!adopt) {
                if (Build.VERSION.SDK_INT >= 33) manager.startProvisionedVpnProfileSession() else manager.startProvisionedVpnProfile()
            }
            withTimeout(45_000) {
                while (true) {
                    check(generations.get() == token) { "IKEv2 startup superseded" }
                    if (Build.VERSION.SDK_INT >= 33) {
                        val platform = manager.provisionedVpnProfileState?.state
                        check(platform != VpnProfileState.STATE_FAILED) { "IKEv2 connection failed" }
                        if (platform == VpnProfileState.STATE_CONNECTED && EngineNetworkProbe.ownedVpn(service)?.let { EngineNetworkProbe.probe(it) } == true) break
                    } else if (EngineNetworkProbe.ownedVpn(service)?.let { EngineNetworkProbe.probe(it) } == true) break
                    delay(500)
                }
            }
            startedAt = SystemClock.elapsedRealtime()
            publish(service, VpnState.Started)
            service.updateNotification(service.getString(R.string.notification_connected))
            monitor?.cancel()
            monitor = scope.launch {
                while (generations.get() == token) {
                    delay(1000)
                    val platform = if (Build.VERSION.SDK_INT >= 33) manager.provisionedVpnProfileState else null
                    val lost = if (Build.VERSION.SDK_INT >= 33) platform?.state in listOf(VpnProfileState.STATE_FAILED, VpnProfileState.STATE_DISCONNECTED)
                        else EngineNetworkProbe.ownedVpn(service) == null
                    val mandatory = platform?.isAlwaysOn == true || platform?.isLockdownEnabled == true ||
                        VpnRuntimeStateStore.readAlwaysOn(service) || VpnRuntimeStateStore.readLockdown(service)
                    if (lost) {
                        if (mandatory) {
                            // Android owns recovery under mandatory policy. Keep the provisioned profile and ownership.
                            if (currentState != VpnState.Starting) { startedAt = 0L; publish(service, VpnState.Starting) }
                        } else { mutex.withLock { if (generations.get() == token) release(service) }; break }
                    } else if (currentState == VpnState.Starting &&
                        (Build.VERSION.SDK_INT < 33 || platform?.state == VpnProfileState.STATE_CONNECTED) &&
                        EngineNetworkProbe.ownedVpn(service)?.let { EngineNetworkProbe.probe(it) } == true) {
                        startedAt = SystemClock.elapsedRealtime(); publish(service, VpnState.Started)
                    }
                }
            }
        } catch (error: Throwable) {
            withContext(NonCancellable) {
                if (release(service, stopService = false) && error !is CancellationException) {
                    publish(service, VpnState.Error("IKEv2 could not establish a verified connection")); service.stopSelf()
                }
            }
            if (error is CancellationException) throw error
        }
    }
    @RequiresApi(30)
    private suspend fun release(context: Context, stopService: Boolean = true): Boolean {
        generations.incrementAndGet()
        val watching = monitor; monitor = null
        if (watching !== currentCoroutineContext().job) watching?.cancel()
        publish(context, VpnState.Stopping)
        val manager = context.getSystemService(VpnManager::class.java)
        val stopped = runCatching {
            val stopRequest = runCatching { manager.stopProvisionedVpnProfile() }
            if (stopRequest.isFailure && EngineNetworkProbe.ownedVpn(context) != null) throw stopRequest.exceptionOrNull()!!
            withTimeout(10_000) {
                while (EngineNetworkProbe.ownedVpn(context) != null) delay(200)
            }
            runCatching { manager.deleteProvisionedVpnProfile() }
        }.isSuccess
        if (!stopped) return false
        activeProfile = null; startedAt = 0
        EngineProfileStore(context).rememberPlatformProfile(null)
        publish(context, VpnState.Stopped)
        if (stopService) context.stopService(Intent(context, EnginePlatformService::class.java))
        return true
    }
    @RequiresApi(30)
    suspend fun releaseForReplacement(context: Context): Boolean {
        startupJob?.cancelAndJoin()
        return mutex.withLock { release(context) }
    }
    fun restore(context: Context) {
        if (Build.VERSION.SDK_INT < 30 || EngineProfileStore(context).platformProfileId() == null) return
        scope.launch {
            val running = withContext(Dispatchers.IO) {
                if (Build.VERSION.SDK_INT >= 33) context.getSystemService(VpnManager::class.java).provisionedVpnProfileState?.state?.let { it != VpnProfileState.STATE_DISCONNECTED } == true
                else EngineNetworkProbe.ownedVpn(context) != null
            }
            if (running) dispatch(context, "restore")
            else { EngineProfileStore(context).rememberPlatformProfile(null); publish(context, VpnState.Stopped) }
        }
    }
    private fun publish(context: Context, state: VpnState) {
        currentState = state
        if (context is EnginePlatformService) when (state) {
            VpnState.Starting -> context.updateNotification(context.getString(R.string.notification_starting))
            VpnState.Started -> context.updateNotification(context.getString(R.string.notification_connected))
            VpnState.Stopping -> context.updateNotification(context.getString(R.string.engine_release_pending))
            else -> Unit
        }
        val managerState = if (Build.VERSION.SDK_INT >= 33) context.getSystemService(VpnManager::class.java)?.provisionedVpnProfileState else null
        val alwaysOn = managerState?.isAlwaysOn ?: VpnRuntimeStateStore.readAlwaysOn(context)
        val lockdown = managerState?.isLockdownEnabled ?: VpnRuntimeStateStore.readLockdown(context)
        val profile = activeProfile
        VpnRuntimeStateStore.save(context, state, startedAt, connectionDetails = profile?.let { it.name + " · IKEv2" }.orEmpty(),
            activeSubscriptionId = EngineProfile.SOURCE_ID, activeConnectionTag = profile?.name.orEmpty(), activeConnectionFingerprint = profile?.id.orEmpty(),
            chainHopCount = 1, alwaysOn = alwaysOn, lockdown = lockdown)
        context.sendBroadcast(Intent(Actions.STATE_CHANGED).setPackage(context.packageName).putExtra(Actions.EXTRA_STATE, state.wireName)
            .putExtra(Actions.EXTRA_ERROR, (state as? VpnState.Error)?.message.orEmpty()).putExtra(Actions.EXTRA_SESSION_STARTED_AT_ELAPSED_MS, startedAt)
            .putExtra(Actions.EXTRA_CONNECTION_DETAILS, profile?.let { it.name + " · IKEv2" }.orEmpty())
            .putExtra(Actions.EXTRA_ACTIVE_SUBSCRIPTION_ID, EngineProfile.SOURCE_ID).putExtra(Actions.EXTRA_ACTIVE_CONNECTION_TAG, profile?.name.orEmpty())
            .putExtra(Actions.EXTRA_ACTIVE_CONNECTION_FINGERPRINT, profile?.id.orEmpty()).putExtra(Actions.EXTRA_ALWAYS_ON, alwaysOn).putExtra(Actions.EXTRA_LOCKDOWN, lockdown))
        WhiteDnsTileService.requestTileRefresh(context)
        VpnWidgetProvider.refresh(context)
    }
}

class EnginePlatformService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        updateNotification(getString(if (VpnRuntimeStateStore.read(this) == VpnState.Started) R.string.notification_connected else R.string.notification_starting))
        if (Build.VERSION.SDK_INT >= 30) scope.launch { PlatformIkev2Controller.handle(this@EnginePlatformService, intent?.action ?: Actions.CONNECT) }
        else stopSelf()
        return START_NOT_STICKY
    }
    fun updateNotification(message: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("engine-platform", "IKEv2", NotificationManager.IMPORTANCE_LOW))
        val main = PendingIntent.getActivity(this, 31, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 32, Intent(this, EnginePlatformService::class.java).setAction(Actions.DISCONNECT), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        startForeground(31, NotificationCompat.Builder(this, "engine-platform").setSmallIcon(R.drawable.ic_vpn_tab)
            .setContentTitle(getString(R.string.app_name)).setContentText(message).setContentIntent(main).setOngoing(true)
            .addAction(0, getString(R.string.engine_disconnect), stop).build())
    }
    override fun onDestroy() { scope.cancel(); super.onDestroy() }
}

internal object RouteServiceDispatcher {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    fun dispatch(context: Context, action: String) {
        val app = context.applicationContext
        if (Build.VERSION.SDK_INT >= 30 && PlatformIkev2Controller.owns(app)) {
            if (action == Actions.DISCONNECT) { PlatformIkev2Controller.dispatch(app, action); return }
            val selected = try {
                EngineProfileStore(app).selectedEngineId()?.let { id ->
                    val profile = EngineProfileStore(app).profile(id) ?: error("Selected engine profile is missing")
                    if (action != Actions.DISCONNECT) EnginePreflight.validate(profile, EngineNativeAvailability.check(app, profile),
                        ConnectionModePolicy.shouldStartTun(ConnectionModePreferenceStore(app).read(), VpnRuntimeStateStore.readAlwaysOn(app), VpnRuntimeStateStore.readLockdown(app)),
                        VpnRuntimeStateStore.readLockdown(app))
                    profile
                }
            } catch (_: Exception) {
                android.widget.Toast.makeText(app, R.string.engine_invalid, android.widget.Toast.LENGTH_LONG).show()
                return
            }
            if (action == Actions.DISCONNECT || selected?.kind == EngineKind.IKEV2) { PlatformIkev2Controller.dispatch(app, action); return }
            scope.launch {
                if (PlatformIkev2Controller.releaseForReplacement(app)) start(app, Actions.CONNECT)
            }
        } else start(app, action)
    }
    private fun start(context: Context, action: String) {
        val intent = Intent(context, WhiteDnsVpnService::class.java).setAction(action).putExtra(Actions.EXTRA_APP_INITIATED, true)
        if (action == Actions.CONNECT) context.startForegroundService(intent) else context.startService(intent)
    }
}
