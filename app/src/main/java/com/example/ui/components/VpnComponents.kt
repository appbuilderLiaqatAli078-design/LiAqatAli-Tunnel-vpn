package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ripple
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.model.VpnState
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.ConnectingAmber
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.theme.DisconnectedRed
import com.example.ui.theme.NeutralGrey
import java.util.Locale

@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 20.dp,
    borderColor: Color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f),
    contentPadding: PaddingValues = PaddingValues(16.dp),
    content: @Composable () -> Unit
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(cornerRadius),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
        ),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Box(modifier = Modifier.padding(contentPadding)) {
            content()
        }
    }
}

@Composable
fun StatusBadge(
    state: VpnState,
    modifier: Modifier = Modifier
) {
    val (statusText, color) = when (state) {
        is VpnState.Connected -> "CONNECTED" to ConnectedGreen
        is VpnState.Connecting -> "CONNECTING..." to ConnectingAmber
        is VpnState.StartingEngine -> "STARTING ENGINE" to ConnectingAmber
        is VpnState.Validating -> "VALIDATING" to ConnectingAmber
        is VpnState.Reconnecting -> "RECONNECTING (${state.attempt}/${state.maxAttempts})" to ConnectingAmber
        is VpnState.Stopping -> "DISCONNECTING..." to ConnectingAmber
        is VpnState.Error -> "ERROR" to DisconnectedRed
        VpnState.Disconnected -> "DISCONNECTED" to NeutralGrey
        VpnState.RequestingVpnPermission -> "PERMISSION NEEDED" to ConnectingAmber
    }

    Surface(
        modifier = modifier.testTag("status_badge"),
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.15f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.5f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(color)
            )
            Text(
                text = statusText,
                style = MaterialTheme.typography.labelMedium.copy(
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                ),
                color = color
            )
        }
    }
}

@Composable
fun ConnectButton(
    state: VpnState,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.08f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    val (buttonColor, glowColor) = when (state) {
        is VpnState.Connected -> ConnectedGreen to ConnectedGreen.copy(alpha = 0.3f)
        is VpnState.Connecting, is VpnState.StartingEngine, is VpnState.Validating -> ConnectingAmber to ConnectingAmber.copy(alpha = 0.35f)
        is VpnState.Error -> DisconnectedRed to DisconnectedRed.copy(alpha = 0.25f)
        else -> CyanPrimaryDark to CyanPrimaryDark.copy(alpha = 0.25f)
    }

    val animatedColor by animateColorAsState(targetValue = buttonColor, label = "buttonColor")

    Box(
        modifier = modifier
            .size(190.dp)
            .testTag("connect_button_container"),
        contentAlignment = Alignment.Center
    ) {
        // Outer pulsing ring when connecting
        if (state.isBusy) {
            Box(
                modifier = Modifier
                    .size(185.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .border(2.dp, glowColor, CircleShape)
            )
        }

        // Outer glow halo
        Box(
            modifier = Modifier
                .size(170.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        listOf(glowColor, Color.Transparent)
                    )
                )
        )

        // Main Button Surface
        Surface(
            modifier = Modifier
                .size(140.dp)
                .clip(CircleShape)
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = ripple(bounded = true, radius = 70.dp),
                    onClick = onClick
                )
                .testTag("connect_button"),
            shape = CircleShape,
            color = MaterialTheme.colorScheme.surfaceVariant,
            border = BorderStroke(3.dp, animatedColor),
            shadowElevation = 8.dp
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = when {
                        state.isConnected -> Icons.Default.Lock
                        state.isBusy -> Icons.Default.Shield
                        else -> Icons.Default.PowerSettingsNew
                    },
                    contentDescription = "Connection Button",
                    tint = animatedColor,
                    modifier = Modifier.size(46.dp)
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = when {
                        state.isConnected -> "DISCONNECT"
                        state.isBusy -> "STOPPING"
                        else -> "CONNECT"
                    },
                    style = MaterialTheme.typography.labelLarge.copy(
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.2.sp
                    ),
                    color = animatedColor
                )
            }
        }
    }
}

@Composable
fun TrafficStatPill(
    label: String,
    value: String,
    speed: String,
    icon: ImageVector,
    tint: Color,
    modifier: Modifier = Modifier
) {
    GlassCard(
        modifier = modifier,
        cornerRadius = 16.dp,
        contentPadding = PaddingValues(12.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(tint.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = tint,
                    modifier = Modifier.size(20.dp)
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = speed,
                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "Total: $value",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
    val pre = "KMGTPE"[exp - 1]
    return String.format(Locale.US, "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
}

fun formatSpeed(bytesPerSec: Long): String {
    return "${formatBytes(bytesPerSec)}/s"
}
