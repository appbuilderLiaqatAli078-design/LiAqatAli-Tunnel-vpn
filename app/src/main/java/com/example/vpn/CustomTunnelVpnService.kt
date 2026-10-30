package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.data.AppLogger
import com.example.model.ProtocolType
import com.example.model.TrafficStats
import com.example.model.VpnProfile
import com.example.model.VpnState
import com.example.parser.SshTargetParser
import com.example.vpn.engine.HevTunnelManager
import com.example.vpn.engine.SshEngineAdapter
import com.example.vpn.engine.VpnEngineAdapter
import com.example.vpn.engine.XrayEngineAdapter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicLong

class CustomTunnelVpnService : VpnService() {

    private val serviceScope = CoroutineScope(Dispatchers.Default + Job())
    private var statsJob: Job? = null
    private var connectionJob: Job? = null
    private val lifecycleMutex = Mutex()
    private val connectionGeneration = AtomicLong(0L)

    private var tunInterface: ParcelFileDescriptor? = null
    private var currentEngine: VpnEngineAdapter? = null
    private var activeProfileData: VpnProfile? = null
    private var connectedTimestamp: Long = 0L
    private var retryCount = 0

    private val connectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    @Volatile
    private var underlyingNetworkChanged = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLost(network: Network) {
            AppLogger.w(TAG, "Underlying physical network lost")
        }

        override fun onAvailable(network: Network) {
            AppLogger.i(TAG, "Underlying physical network available")
            if (_vpnState.value.isConnected) {
                underlyingNetworkChanged = true
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        AppLogger.i(TAG, "CustomTunnelVpnService created")
        createNotificationChannel()
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
                AppLogger.i(TAG, "Received ACTION_CONNECT for profileId: $profileId")
                promoteToForeground("Initializing VPN tunnel...", false)
                startConnectionFlow()
            }
            ACTION_DISCONNECT -> {
                AppLogger.i(TAG, "Received ACTION_DISCONNECT")
                disconnect()
            }
        }
        return START_NOT_STICKY
    }

    private fun startConnectionFlow() {
        val profile = _activeProfile.value
        if (profile == null) {
            AppLogger.e(TAG, "Cannot connect: activeProfile is null")
            _vpnState.value = VpnState.Error("No profile selected for connection", "ERR_NO_PROFILE")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Guard against duplicate connect requests for the exact same profile while already connecting
        val currentState = _vpnState.value
        if (currentState.isBusy && activeProfileData?.id == profile.id && connectionJob?.isActive == true) {
            AppLogger.w(TAG, "Connection attempt already in progress for ${profile.name}; ignoring duplicate request")
            return
        }

        val myGen = connectionGeneration.incrementAndGet()
        connectionJob?.cancel()
        connectionJob = serviceScope.launch {
            lifecycleMutex.withLock {
                if (myGen != connectionGeneration.get()) return@withLock
                try {
                    // Enforce .ctp security locks before initiating connection
                    if (profile.isExpired) {
                        throw IllegalStateException("Security Lock: This .ctp profile has expired")
                    }
                    if (profile.blockRoot && com.example.security.DeviceSecurityManager.isDeviceRooted(this@CustomTunnelVpnService)) {
                        throw IllegalStateException("Security Lock: This .ctp profile blocks rooted devices")
                    }
                    if (profile.lockedHwid.isNotBlank()) {
                        val deviceHwid = com.example.security.DeviceSecurityManager.getHardwareId(this@CustomTunnelVpnService)
                        if (!profile.lockedHwid.equals(deviceHwid, ignoreCase = true)) {
                            throw IllegalStateException("Security Lock: Profile locked to another Hardware ID ($deviceHwid)")
                        }
                    }

                    // Normalize SSH profile if server address contains user/pass/port in target format (e.g. www.openx.com:80@Test:Test1)
                    var effectiveProfile = profile
                    if (effectiveProfile.protocol == ProtocolType.SSH && (effectiveProfile.server.contains("@") || effectiveProfile.server.startsWith("ssh://"))) {
                        val parsed = SshTargetParser.parse(effectiveProfile.server, effectiveProfile.port)
                        if (parsed != null) {
                            effectiveProfile = effectiveProfile.copy(
                                server = parsed.host,
                                port = parsed.port,
                                sshUsername = if (effectiveProfile.sshUsername.isBlank()) parsed.username else effectiveProfile.sshUsername,
                                password = if (effectiveProfile.password.isBlank()) parsed.password else effectiveProfile.password
                            )
                        }
                    }

                    AppLogger.registerSensitiveHosts(
                        effectiveProfile.server,
                        effectiveProfile.sni,
                        effectiveProfile.wsHost,
                        effectiveProfile.sshSni,
                        effectiveProfile.proxyHost,
                        effectiveProfile.sshChainProxyHost
                    )

                    activeProfileData = effectiveProfile
                    _vpnState.value = VpnState.Validating("Validating server ••••••••••••")
                    updateNotification("Validating connection...", false)

                    // Basic address / port validation
                    if (effectiveProfile.server.isBlank() || effectiveProfile.port !in 1..65535) {
                        throw IllegalArgumentException("Invalid server address or port: ••••••••••••")
                    }

                    _vpnState.value = VpnState.StartingEngine(
                        if (effectiveProfile.protocol == ProtocolType.SSH) "SSH Tunnel Engine" else "Xray Core Engine"
                    )

                    // Sequentially stop any active engine/forwarder BEFORE closing old TUN or creating a new one
                    cleanupSuspend()

                    if (myGen != connectionGeneration.get()) return@withLock

                    // Establish TUN interface
                    val tunPfd = establishTun(effectiveProfile)
                    if (tunPfd == null) {
                        throw IllegalStateException("Failed to establish Android TUN interface")
                    }
                    tunInterface = tunPfd

                    // Select and initialize engine adapter
                    val engine: VpnEngineAdapter = when (effectiveProfile.protocol) {
                        ProtocolType.SSH -> SshEngineAdapter()
                        else -> XrayEngineAdapter()
                    }
                    currentEngine = engine

                    _vpnState.value = VpnState.Connecting(effectiveProfile.name)
                    updateNotification("Connecting to ${effectiveProfile.name}...", false)

                    val started = engine.start(effectiveProfile, this@CustomTunnelVpnService, tunPfd.fd)
                    if (!started) {
                        throw IllegalStateException("Tunnel engine failed to start or attach")
                    }

                    if (myGen != connectionGeneration.get()) {
                        cleanupSuspend()
                        return@withLock
                    }

                    val connectivity = engine.getLastConnectivityResult()
                    val isVerified = connectivity?.verified ?: false
                    val detailText = connectivity?.diagnosticMessage
                        ?: if (isVerified) "Internet Verified" else "Tunnel Connected — Internet Unverified"
                    connectedTimestamp = System.currentTimeMillis()
                    _vpnState.value = VpnState.Connected(
                        profileName = profile.name,
                        connectedSince = connectedTimestamp,
                        engineName = engine.getEngineName(),
                        isInternetVerified = isVerified,
                        verificationDetail = detailText,
                        rttMs = connectivity?.rttMs
                    )
                    retryCount = 0

                    if (isVerified) {
                        AppLogger.i(TAG, "VPN connected and internet verified for ${profile.name} ($detailText)")
                        updateNotification("Connected • Internet Verified (${profile.name})", true)
                    } else {
                        AppLogger.w(
                            TAG,
                            "Tunnel connected to ${profile.name} — internet unverified: $detailText"
                        )
                        updateNotification("Tunnel Connected — Internet Unverified (${profile.name})", true)
                    }

                    startStatsMonitor(myGen)
                } catch (e: Throwable) {
                    if (myGen != connectionGeneration.get()) return@withLock
                    AppLogger.e(TAG, "Connection failed: ${e.message}", e)
                    cleanupSuspend()
                    _vpnState.value = VpnState.Error(
                        message = e.message ?: "Connection failure",
                        code = "ERR_CONNECT_FAILED"
                    )
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    fun notifyTunnelEstablished(
        profileName: String,
        detail: String = "Tunnel established, verifying internet..."
    ) {
        _vpnState.value = VpnState.TunnelEstablished(profileName, detail)
        updateNotification(detail, false)
    }

    private fun establishTun(profile: VpnProfile): ParcelFileDescriptor? {
        AppLogger.i(TAG, "Configuring Android VpnService.Builder TUN device")
        val builder = Builder()
            .setSession("CustomTunnelPro-${profile.name}")
            .setMtu(1500)
            .addAddress("198.18.0.1", 24)
            .addRoute("0.0.0.0", 0)

        // DNS Server configuration
        val dnsPrimary = profile.dnsPrimary.ifBlank { "1.1.1.1" }
        builder.addDnsServer(dnsPrimary)
        if (profile.dnsSecondary.isNotBlank()) {
            builder.addDnsServer(profile.dnsSecondary)
        }
        AppLogger.i(TAG, "TUN DNS set to $dnsPrimary, secondary: ${profile.dnsSecondary}")

        // Deliberate IPv6 leak protection:
        // When blockIpv6 is true, we route IPv6 to a blackhole or do not configure an IPv6 route,
        // blocking unauthorized outside-tunnel IPv6 leakage.
        if (!profile.blockIpv6) {
            try {
                builder.addAddress("fd00::1", 64)
                builder.addRoute("::", 0)
                AppLogger.i(TAG, "IPv6 tunneling route enabled (::/0)")
            } catch (e: Exception) {
                AppLogger.w(TAG, "Could not add IPv6 address to TUN: ${e.message}")
            }
        } else {
            AppLogger.i(TAG, "IPv6 leak protection active: IPv6 traffic isolated")
        }

        // Per-App Split Tunneling (always exclude self package to prevent routing loops)
        val allowedPackages = if (profile.perAppProxy) {
            profile.selectedApps.map { it.trim() }.filter { it.isNotBlank() && it != packageName }
        } else {
            emptyList()
        }
        if (profile.perAppProxy && allowedPackages.isNotEmpty()) {
            for (pkg in allowedPackages) {
                try {
                    builder.addAllowedApplication(pkg)
                    AppLogger.d(TAG, "Split tunneling: including app $pkg")
                } catch (e: Exception) {
                    AppLogger.w(TAG, "Cannot include package $pkg: ${e.message}")
                }
            }
        } else {
            // Prevent routing loops: exclude VPN service's own process from TUN device
            try {
                builder.addDisallowedApplication(packageName)
                AppLogger.d(TAG, "Disallowed self package $packageName from TUN routing to prevent loops")
            } catch (e: Exception) {
                AppLogger.w(TAG, "Could not disallow self package: ${e.message}")
            }
        }

        // Configure underlying networks if available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            builder.setUnderlyingNetworks(null)
        }

        return builder.establish()
    }

    private fun startStatsMonitor(generation: Long) {
        statsJob?.cancel()
        underlyingNetworkChanged = false
        statsJob = serviceScope.launch {
            var backgroundRechecks = 0
            var ticksSinceLastRecheck = 0
            var prevBytesIn = 0L
            var prevBytesOut = 0L
            var stalledTxTicks = 0

            while (isActive && generation == connectionGeneration.get() && _vpnState.value is VpnState.Connected) {
                delay(1500)
                if (generation != connectionGeneration.get()) break
                val stats = HevTunnelManager.getStats()
                if (stats != _trafficStats.value) {
                    _trafficStats.value = stats
                }

                // Track passive one-way traffic stalls (apps actively transmitting bytesOut while bytesIn is frozen at 0)
                if (stats.bytesIn > prevBytesIn) {
                    stalledTxTicks = 0
                } else if (stats.bytesOut > prevBytesOut + 512L) {
                    stalledTxTicks++
                }
                prevBytesIn = stats.bytesIn
                prevBytesOut = stats.bytesOut

                val currentConnected = _vpnState.value as? VpnState.Connected ?: break

                // Non-disruptive self-healing: ONLY runs if physical network switched or >=12s of continuous outbound-only stall
                if (underlyingNetworkChanged || stalledTxTicks >= 8) {
                    val reason = if (underlyingNetworkChanged) "physical network transition" else "outbound traffic stall"
                    underlyingNetworkChanged = false
                    stalledTxTicks = 0
                    val engine = currentEngine
                    if (engine != null && generation == connectionGeneration.get()) {
                        AppLogger.i(TAG, "Detected $reason; triggering non-disruptive tunnel recovery...")
                        val recovered = engine.recoverIfStalled()
                        val latestCheck = engine.getLastConnectivityResult()
                        if (recovered && latestCheck != null && latestCheck.verified && generation == connectionGeneration.get()) {
                            val latestState = _vpnState.value as? VpnState.Connected
                            if (latestState != null && !latestState.isInternetVerified) {
                                _vpnState.value = latestState.copy(
                                    isInternetVerified = true,
                                    verificationDetail = latestCheck.diagnosticMessage,
                                    rttMs = latestCheck.rttMs
                                )
                                updateNotification(
                                    "Connected • Internet Verified (${latestState.profileName})",
                                    true
                                )
                            }
                        }
                    }
                    continue
                }

                if (!currentConnected.isInternetVerified && backgroundRechecks < 3) {
                    ticksSinceLastRecheck++
                    if (stats.bytesIn > 0L || ticksSinceLastRecheck >= 5) {
                        ticksSinceLastRecheck = 0
                        backgroundRechecks++
                        val engine = currentEngine
                        val recheck = engine?.recheckConnectivity()
                        if (recheck != null && recheck.verified && generation == connectionGeneration.get()) {
                            _vpnState.value = currentConnected.copy(
                                isInternetVerified = true,
                                verificationDetail = recheck.diagnosticMessage,
                                rttMs = recheck.rttMs
                            )
                            AppLogger.i(
                                TAG,
                                "Tunnel internet connectivity verified for ${currentConnected.profileName} (${recheck.diagnosticMessage})"
                            )
                            updateNotification(
                                "Connected • Internet Verified (${currentConnected.profileName})",
                                true
                            )
                        }
                    }
                }
            }
        }
    }

    private fun disconnect() {
        val myGen = connectionGeneration.incrementAndGet()
        connectionJob?.cancel()
        connectionJob = null
        serviceScope.launch {
            lifecycleMutex.withLock {
                if (myGen != connectionGeneration.get()) return@withLock
                _vpnState.value = VpnState.Stopping
                AppLogger.i(TAG, "Disconnecting VPN...")
                cleanupSuspend()
                _vpnState.value = VpnState.Disconnected
                _trafficStats.value = TrafficStats()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private suspend fun cleanupSuspend() {
        statsJob?.cancel()
        statsJob = null

        val engineToStop = currentEngine
        currentEngine = null
        if (engineToStop != null) {
            try {
                // Stop active forwarding components (HEV + Xray/SSH) BEFORE closing the TUN fd
                engineToStop.stop()
            } catch (e: Exception) {
                AppLogger.w(TAG, "Error stopping current engine: ${e.message}")
            }
        }

        val tunToClose = tunInterface
        tunInterface = null
        if (tunToClose != null) {
            try {
                tunToClose.close()
                AppLogger.d(TAG, "Closed TUN file descriptor")
            } catch (e: Exception) {
                AppLogger.w(TAG, "Error closing TUN file descriptor: ${e.message}")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        AppLogger.i(TAG, "CustomTunnelVpnService destroyed")
        connectionGeneration.incrementAndGet()
        connectionJob?.cancel()
        runBlocking {
            cleanupSuspend()
        }
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
            // Ignored if not registered
        }
        _vpnState.value = VpnState.Disconnected
    }

    override fun onRevoke() {
        super.onRevoke()
        AppLogger.w(TAG, "VPN permission revoked by user or system")
        disconnect()
    }

    private fun registerNetworkCallback() {
        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            connectivityManager.registerNetworkCallback(request, networkCallback)
        } catch (e: Exception) {
            AppLogger.w(TAG, "Could not register network callback: ${e.message}")
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Custom Tunnel Pro Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows active VPN connection status and traffic"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String, isConnected: Boolean): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, CustomTunnelVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this,
            1,
            disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Custom Tunnel Pro")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(isConnected)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setContentIntent(openPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)

        if (isConnected) {
            builder.addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Disconnect",
                disconnectPendingIntent
            )
        }

        return builder.build()
    }

    private fun promoteToForeground(statusText: String, isConnected: Boolean) {
        val notification = buildNotification(statusText, isConnected)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            AppLogger.e(TAG, "Failed startForeground: ${e.message}", e)
        }
    }

    private fun updateNotification(statusText: String, isConnected: Boolean) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(statusText, isConnected))
    }

    companion object {
        const val TAG = "CustomTunnelVpnService"
        const val CHANNEL_ID = "ctp_vpn_status_channel"
        const val NOTIFICATION_ID = 2001

        const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"
        const val EXTRA_PROFILE_ID = "com.example.vpn.EXTRA_PROFILE_ID"

        private val _vpnState = MutableStateFlow<VpnState>(VpnState.Disconnected)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private val _activeProfile = MutableStateFlow<VpnProfile?>(null)
        val activeProfile: StateFlow<VpnProfile?> = _activeProfile.asStateFlow()

        fun setActiveProfile(profile: VpnProfile?) {
            _activeProfile.value = profile
        }

        fun startVpn(context: Context, profile: VpnProfile) {
            setActiveProfile(profile)
            val intent = Intent(context, CustomTunnelVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_PROFILE_ID, profile.id)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stopVpn(context: Context) {
            val intent = Intent(context, CustomTunnelVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            context.startService(intent)
        }
    }
}
