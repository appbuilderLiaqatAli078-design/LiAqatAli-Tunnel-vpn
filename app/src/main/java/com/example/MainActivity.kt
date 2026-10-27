package com.example

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import com.example.model.ProtocolType
import com.example.model.VpnProfile
import com.example.ui.screens.ConnectionDetailsScreen
import com.example.ui.screens.DnsRoutingScreen
import com.example.ui.screens.HomeScreen
import com.example.ui.screens.ImportScreen
import com.example.ui.screens.LogsScreen
import com.example.ui.screens.ProfileEditScreen
import com.example.ui.screens.ProfilesScreen
import com.example.ui.screens.SettingsScreen
import com.example.ui.theme.AegisTunnelTheme
import com.example.ui.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {
    private val viewModel: VpnViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val settings by viewModel.settings.collectAsState()
            val darkTheme = when (settings.theme) {
                "dark" -> true
                "light" -> false
                else -> isSystemInDarkTheme()
            }

            AegisTunnelTheme(darkTheme = darkTheme) {
                MainAppContent(viewModel = viewModel)
            }
        }
    }
}

enum class ScreenTab(val title: String) {
    HOME("Home"),
    PROFILES("Profiles"),
    DETAILS("Diagnostics"),
    DNS("DNS & Route"),
    LOGS("Logs"),
    SETTINGS("Settings")
}

@Composable
fun MainAppContent(viewModel: VpnViewModel) {
    val context = LocalContext.current
    var currentTab by remember { mutableStateOf(ScreenTab.HOME) }
    var editingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var isCreatingNew by remember { mutableStateOf(false) }
    var newProtocol by remember { mutableStateOf(ProtocolType.VLESS) }
    var isImporting by remember { mutableStateOf(false) }

    // VPN Permission Launcher
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.connect(context)
        } else {
            Toast.makeText(context, "VPN connection cancelled: permission required", Toast.LENGTH_LONG).show()
        }
    }

    // Notification Permission Launcher (Android 13+)
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { /* handled silently */ }

    androidx.compose.runtime.LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    val onConnectAction: () -> Unit = {
        val vpnState = viewModel.vpnState.value
        if (vpnState.isConnected || vpnState.isBusy) {
            viewModel.disconnect(context)
        } else {
            val prepareIntent = viewModel.prepareVpnIntent(context)
            if (prepareIntent != null) {
                vpnPermissionLauncher.launch(prepareIntent)
            } else {
                viewModel.connect(context)
            }
        }
    }

    val onExportAction: (String) -> Unit = { exportedContent ->
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("VPN Config", exportedContent))
        Toast.makeText(context, "Config copied to clipboard", Toast.LENGTH_SHORT).show()

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, exportedContent)
        }
        context.startActivity(Intent.createChooser(shareIntent, "Share VPN Profile"))
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            if (!isImporting && editingProfile == null && !isCreatingNew) {
                NavigationBar(modifier = Modifier.testTag("main_navigation_bar")) {
                    NavigationBarItem(
                        selected = currentTab == ScreenTab.HOME,
                        onClick = { currentTab = ScreenTab.HOME },
                        icon = { Icon(Icons.Default.Shield, contentDescription = "Home") },
                        label = { Text("Home", style = MaterialTheme.typography.labelSmall, maxLines = 1, softWrap = false) },
                        modifier = Modifier.testTag("tab_home")
                    )
                    NavigationBarItem(
                        selected = currentTab == ScreenTab.PROFILES,
                        onClick = { currentTab = ScreenTab.PROFILES },
                        icon = { Icon(Icons.Default.Layers, contentDescription = "Profiles") },
                        label = { Text("Profiles", style = MaterialTheme.typography.labelSmall, maxLines = 1, softWrap = false) },
                        modifier = Modifier.testTag("tab_profiles")
                    )
                    NavigationBarItem(
                        selected = currentTab == ScreenTab.DNS,
                        onClick = { currentTab = ScreenTab.DNS },
                        icon = { Icon(Icons.Default.Dns, contentDescription = "DNS & Routing") },
                        label = { Text("DNS", style = MaterialTheme.typography.labelSmall, maxLines = 1, softWrap = false) },
                        modifier = Modifier.testTag("tab_dns")
                    )
                    NavigationBarItem(
                        selected = currentTab == ScreenTab.LOGS,
                        onClick = { currentTab = ScreenTab.LOGS },
                        icon = { Icon(Icons.Default.Terminal, contentDescription = "Logs") },
                        label = { Text("Logs", style = MaterialTheme.typography.labelSmall, maxLines = 1, softWrap = false) },
                        modifier = Modifier.testTag("tab_logs")
                    )
                    NavigationBarItem(
                        selected = currentTab == ScreenTab.SETTINGS,
                        onClick = { currentTab = ScreenTab.SETTINGS },
                        icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                        label = { Text("Settings", style = MaterialTheme.typography.labelSmall, maxLines = 1, softWrap = false) },
                        modifier = Modifier.testTag("tab_settings")
                    )
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when {
                isImporting -> {
                    BackHandler { isImporting = false }
                    ImportScreen(
                        viewModel = viewModel,
                        onImportSuccess = {
                            isImporting = false
                            currentTab = ScreenTab.PROFILES
                        }
                    )
                }
                editingProfile != null || isCreatingNew -> {
                    BackHandler {
                        editingProfile = null
                        isCreatingNew = false
                    }
                    ProfileEditScreen(
                        initialProfile = editingProfile,
                        defaultProtocol = newProtocol,
                        onSaveProfile = { saved ->
                            viewModel.saveProfile(saved)
                            editingProfile = null
                            isCreatingNew = false
                        },
                        onCancel = {
                            editingProfile = null
                            isCreatingNew = false
                        }
                    )
                }
                currentTab == ScreenTab.HOME -> {
                    HomeScreen(
                        viewModel = viewModel,
                        onNavigateToProfiles = { currentTab = ScreenTab.PROFILES },
                        onNavigateToDetails = { currentTab = ScreenTab.DETAILS },
                        onNavigateToDns = { currentTab = ScreenTab.DNS },
                        onConnectClick = onConnectAction
                    )
                }
                currentTab == ScreenTab.PROFILES -> {
                    BackHandler { currentTab = ScreenTab.HOME }
                    ProfilesScreen(
                        viewModel = viewModel,
                        onEditProfile = { profile -> editingProfile = profile },
                        onCreateProfile = { proto ->
                            newProtocol = proto
                            isCreatingNew = true
                        },
                        onNavigateToImport = { isImporting = true },
                        onExportProfile = onExportAction
                    )
                }
                currentTab == ScreenTab.DETAILS -> {
                    BackHandler { currentTab = ScreenTab.HOME }
                    ConnectionDetailsScreen(
                        viewModel = viewModel,
                        onNavigateBack = { currentTab = ScreenTab.HOME }
                    )
                }
                currentTab == ScreenTab.DNS -> {
                    BackHandler { currentTab = ScreenTab.HOME }
                    DnsRoutingScreen(viewModel = viewModel)
                }
                currentTab == ScreenTab.LOGS -> {
                    BackHandler { currentTab = ScreenTab.HOME }
                    LogsScreen(viewModel = viewModel)
                }
                currentTab == ScreenTab.SETTINGS -> {
                    BackHandler { currentTab = ScreenTab.HOME }
                    SettingsScreen(
                        viewModel = viewModel,
                        onNavigateToDns = { currentTab = ScreenTab.DNS }
                    )
                }
            }
        }
    }
}
