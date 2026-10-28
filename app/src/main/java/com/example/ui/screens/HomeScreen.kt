package com.example.ui.screens

import android.os.Build
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForwardIos
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnState
import com.example.ui.components.ConnectButton
import com.example.ui.components.GlassCard
import com.example.ui.components.StatusBadge
import com.example.ui.components.TrafficStatPill
import com.example.ui.components.formatBytes
import com.example.ui.components.formatSpeed
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.viewmodel.VpnViewModel
import kotlinx.coroutines.delay
import java.util.Locale

@Composable
fun HomeScreen(
    viewModel: VpnViewModel,
    onNavigateToProfiles: () -> Unit,
    onNavigateToDetails: () -> Unit,
    onNavigateToDns: () -> Unit,
    onConnectClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val vpnState by viewModel.vpnState.collectAsState()
    val trafficStats by viewModel.trafficStats.collectAsState()
    val selectedProfile by viewModel.selectedProfile.collectAsState()
    val settings by viewModel.settings.collectAsState()

    var elapsedSeconds by remember { mutableLongStateOf(0L) }

    LaunchedEffect(vpnState) {
        if (vpnState is VpnState.Connected) {
            val since = (vpnState as VpnState.Connected).connectedSince
            while (true) {
                elapsedSeconds = (System.currentTimeMillis() - since) / 1000
                delay(1000)
            }
        } else {
            elapsedSeconds = 0L
        }
    }

    val abi = remember {
        val abis = Build.SUPPORTED_ABIS
        if (abis.isNotEmpty()) abis[0] else "arm64-v8a"
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Top Header: Branding + Architecture Pill
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Custom Tunnel Pro",
                    style = MaterialTheme.typography.headlineMedium.copy(fontWeight = FontWeight.ExtraBold),
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = if (settings.proMode) "Pro Tunnel Mode • Liaqat Ali (@LiaqatAliPro)" else "Simple Mode • @LiaqatAliPro",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .clip(CircleShape)
                            .background(CyanPrimaryDark)
                    )
                    Text(
                        text = abi,
                        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        // Active State Badge
        StatusBadge(state = vpnState)

        // Intermediate TunnelEstablished verification status
        AnimatedVisibility(visible = vpnState is VpnState.TunnelEstablished) {
            val detail = (vpnState as? VpnState.TunnelEstablished)?.detail ?: "Tunnel established, verifying internet..."
            Text(
                text = detail,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }

        // Session Timer (if connected)
        AnimatedVisibility(visible = vpnState is VpnState.Connected) {
            val hours = elapsedSeconds / 3600
            val minutes = (elapsedSeconds % 3600) / 60
            val seconds = elapsedSeconds % 60
            val formattedTime = String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)

            Surface(
                shape = RoundedCornerShape(12.dp),
                color = ConnectedGreen.copy(alpha = 0.1f)
            ) {
                Text(
                    text = formattedTime,
                    style = MaterialTheme.typography.headlineSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold
                    ),
                    color = ConnectedGreen,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
                )
            }
        }

        // Main Connect Button
        ConnectButton(
            state = vpnState,
            onClick = onConnectClick,
            modifier = Modifier.padding(vertical = 12.dp)
        )

        // Selected Profile Card
        GlassCard(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onNavigateToProfiles() }
                .testTag("selected_profile_card"),
            cornerRadius = 20.dp
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Surface(
                        shape = CircleShape,
                        color = Color(selectedProfile?.protocol?.badgeColorHex ?: 0xFF00E5FF).copy(alpha = 0.2f),
                        modifier = Modifier.size(44.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Default.Shield,
                                contentDescription = null,
                                tint = Color(selectedProfile?.protocol?.badgeColorHex ?: 0xFF00E5FF),
                                modifier = Modifier.size(24.dp)
                            )
                        }
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = selectedProfile?.name ?: "No Profile Selected",
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = selectedProfile?.protocol?.displayName ?: "Select config",
                                style = MaterialTheme.typography.labelSmall,
                                color = Color(selectedProfile?.protocol?.badgeColorHex ?: 0xFF00E5FF)
                            )
                            Text(
                                text = "•",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = selectedProfile?.maskedEndpoint ?: "tap to select",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false).testTag("home_masked_host")
                            )
                            if (selectedProfile?.isLocked == true) {
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = CyanPrimaryDark.copy(alpha = 0.15f)
                                ) {
                                    Text(
                                        text = "LOCKED .CTP",
                                        style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, fontWeight = FontWeight.Bold),
                                        color = CyanPrimaryDark,
                                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp)
                                    )
                                }
                            }
                        }
                        if (!selectedProfile?.creatorMessage.isNullOrBlank()) {
                            Text(
                                text = selectedProfile?.creatorMessage ?: "",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }

                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForwardIos,
                    contentDescription = "Switch Profile",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
            }
        }

        // Live Traffic Gauges (Pro mode or when connected)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            TrafficStatPill(
                label = "DOWNLOAD",
                value = formatBytes(trafficStats.bytesIn),
                speed = formatSpeed(trafficStats.speedInBytesPerSec),
                icon = Icons.Default.ArrowDownward,
                tint = CyanPrimaryDark,
                modifier = Modifier.weight(1f)
            )

            TrafficStatPill(
                label = "UPLOAD",
                value = formatBytes(trafficStats.bytesOut),
                speed = formatSpeed(trafficStats.speedOutBytesPerSec),
                icon = Icons.Default.ArrowUpward,
                tint = Color(0xFF38BDF8),
                modifier = Modifier.weight(1f)
            )
        }

        // Quick Security & Engine Overview Pills
        GlassCard(
            modifier = Modifier.fillMaxWidth(),
            cornerRadius = 16.dp
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Dns,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = "Tunnel DNS",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        text = selectedProfile?.dnsPrimary ?: settings.defaultDns,
                        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.primary,
                        textAlign = TextAlign.End,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = ConnectedGreen,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = "IPv6 Leak Isolation",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        text = if (selectedProfile?.blockIpv6 == false) "Routed (::/0)" else "Strict Protected",
                        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                        color = ConnectedGreen,
                        textAlign = TextAlign.End,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        // Error message banner if state is Error
        AnimatedVisibility(visible = vpnState is VpnState.Error) {
            val err = vpnState as? VpnState.Error
            GlassCard(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 16.dp,
                borderColor = MaterialTheme.colorScheme.error.copy(alpha = 0.5f)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.ErrorOutline,
                        contentDescription = "Error",
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(24.dp)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Connection Failed",
                            style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.error,
                            maxLines = 1
                        )
                        Text(
                            text = err?.message ?: "Unknown error",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 4,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}
