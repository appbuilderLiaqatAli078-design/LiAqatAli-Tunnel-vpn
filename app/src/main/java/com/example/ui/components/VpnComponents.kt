package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.layout.fillMaxSize
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChangeIgnoreConsumed
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
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
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.sin

/**
 * Zero-drain interactive liquid wave modifier & renderer.
 * Sleeps at 0 FPS when idle; wakes immediately on finger touch/swipe or state change,
 * then damps smoothly back to rest (~1.2s) to preserve battery life.
 */
@Composable
fun InteractiveLiquidLayer(
    liquidColor: Color,
    baseFillFraction: Float = 0.28f,
    stateKey: Any? = null,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    var isTouching by remember { mutableStateOf(false) }
    var waveEnergy by remember { mutableFloatStateOf(0f) }
    var wavePhase by remember { mutableFloatStateOf(0f) }
    var tiltOffset by remember { mutableFloatStateOf(0f) }
    var verticalSplash by remember { mutableFloatStateOf(0f) }
    var wakeTrigger by remember { mutableIntStateOf(0) }

    // Brief ripple when state changes (e.g. Connected / Disconnected), then sleeps at 0 FPS
    LaunchedEffect(stateKey) {
        if (stateKey != null) {
            waveEnergy = maxOf(waveEnergy, 0.75f)
            wakeTrigger++
        }
    }

    // Physics loop ONLY runs while finger is touching or waveEnergy > 0.01f.
    // Once damped, coroutine exits completely -> 0 FPS idle CPU/GPU usage.
    LaunchedEffect(isTouching, wakeTrigger) {
        var lastNanos = 0L
        while (isTouching || waveEnergy > 0.01f || abs(tiltOffset) > 0.01f) {
            withFrameNanos { nanos ->
                val dt = if (lastNanos == 0L) 0.016f else ((nanos - lastNanos) / 1_000_000_000f).coerceIn(0.001f, 0.05f)
                lastNanos = nanos
                val speed = 4.2f + (waveEnergy * 5.5f)
                wavePhase = (wavePhase + dt * speed) % (2f * Math.PI.toFloat() * 10f)
                if (!isTouching) {
                    waveEnergy *= 0.93f
                    tiltOffset *= 0.90f
                    verticalSplash *= 0.90f
                    if (waveEnergy < 0.01f && abs(tiltOffset) < 0.01f) {
                        waveEnergy = 0f
                        tiltOffset = 0f
                        verticalSplash = 0f
                    }
                }
            }
        }
    }

    Box(
        modifier = modifier.pointerInput(Unit) {
            awaitPointerEventScope {
                while (true) {
                    val event = awaitPointerEvent(PointerEventPass.Initial)
                    val changes = event.changes
                    val anyPressed = changes.any { it.pressed }
                    if (anyPressed) {
                        isTouching = true
                        var dxSum = 0f
                        var dySum = 0f
                        changes.forEach { change ->
                            val delta = change.positionChangeIgnoreConsumed()
                            dxSum += delta.x
                            dySum += delta.y
                        }
                        val widthPx = size.width.coerceAtLeast(1).toFloat()
                        val heightPx = size.height.coerceAtLeast(1).toFloat()
                        val normalizedDx = (dxSum / widthPx).coerceIn(-0.6f, 0.6f)
                        val normalizedDy = (dySum / heightPx).coerceIn(-0.5f, 0.5f)
                        val swipeIntensity = (abs(normalizedDx) + abs(normalizedDy)) * 4.5f
                        waveEnergy = (waveEnergy + 0.25f + swipeIntensity).coerceIn(0.55f, 1.85f)
                        tiltOffset = (tiltOffset + normalizedDx * 1.6f).coerceIn(-1f, 1f)
                        verticalSplash = (verticalSplash - normalizedDy * 0.45f).coerceIn(-0.18f, 0.22f)
                        wakeTrigger++
                    } else if (isTouching) {
                        isTouching = false
                        wakeTrigger++
                    }
                }
            }
        }
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val w = size.width
            val h = size.height
            if (w > 0f && h > 0f) {
                val effectiveFill = (baseFillFraction + verticalSplash + (waveEnergy * 0.06f)).coerceIn(0.10f, 0.85f)
                val baseWaterY = h * (1f - effectiveFill)
                val maxAmp = h * 0.09f * (0.22f + waveEnergy * 0.78f)
                val secondaryAmp = maxAmp * 0.65f
                val step = (w / 28f).coerceAtLeast(4f)

                // Back liquid wave
                val backPath = Path().apply {
                    moveTo(0f, h)
                    var x = 0f
                    while (x <= w + step) {
                        val clampedX = x.coerceAtMost(w)
                        val normX = (clampedX / w) - 0.5f
                        val tiltY = normX * tiltOffset * (h * 0.22f)
                        val y = baseWaterY - tiltY +
                            sin((clampedX / w) * 2.4f * Math.PI.toFloat() - wavePhase * 1.15f) * secondaryAmp +
                            cos((clampedX / w) * 4.2f * Math.PI.toFloat() + wavePhase * 0.8f) * (secondaryAmp * 0.4f)
                        lineTo(clampedX, y.coerceIn(0f, h))
                        x += step
                    }
                    lineTo(w, h)
                    close()
                }

                drawPath(
                    path = backPath,
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            liquidColor.copy(alpha = 0.20f + (waveEnergy * 0.08f).coerceAtMost(0.15f)),
                            liquidColor.copy(alpha = 0.06f)
                        ),
                        startY = (baseWaterY - maxAmp).coerceAtLeast(0f),
                        endY = h
                    )
                )

                // Front liquid wave
                val frontPath = Path().apply {
                    moveTo(0f, h)
                    var x = 0f
                    while (x <= w + step) {
                        val clampedX = x.coerceAtMost(w)
                        val normX = (clampedX / w) - 0.5f
                        val tiltY = normX * tiltOffset * (h * 0.30f)
                        val y = baseWaterY + tiltY +
                            sin((clampedX / w) * 2.0f * Math.PI.toFloat() + wavePhase) * maxAmp +
                            cos((clampedX / w) * 3.6f * Math.PI.toFloat() - wavePhase * 1.3f) * (maxAmp * 0.35f)
                        lineTo(clampedX, y.coerceIn(0f, h))
                        x += step
                    }
                    lineTo(w, h)
                    close()
                }

                drawPath(
                    path = frontPath,
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            liquidColor.copy(alpha = 0.32f + (waveEnergy * 0.12f).coerceAtMost(0.20f)),
                            liquidColor.copy(alpha = 0.12f)
                        ),
                        startY = (baseWaterY - maxAmp).coerceAtLeast(0f),
                        endY = h
                    )
                )
            }
        }
        content()
    }
}

@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    cornerRadius: Dp = 20.dp,
    borderColor: Color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f),
    contentPadding: PaddingValues = PaddingValues(16.dp),
    enableLiquidWave: Boolean = false,
    liquidColor: Color = CyanPrimaryDark,
    liquidFillFraction: Float = 0.32f,
    liquidStateKey: Any? = null,
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
        if (enableLiquidWave) {
            InteractiveLiquidLayer(
                liquidColor = liquidColor,
                baseFillFraction = liquidFillFraction,
                stateKey = liquidStateKey,
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(modifier = Modifier.padding(contentPadding)) {
                    content()
                }
            }
        } else {
            Box(modifier = Modifier.padding(contentPadding)) {
                content()
            }
        }
    }
}

@Composable
fun StatusBadge(
    state: VpnState,
    modifier: Modifier = Modifier
) {
    val (statusText, color) = when (state) {
        is VpnState.Connected -> if (state.isInternetVerified) {
            "CONNECTED • INTERNET VERIFIED" to ConnectedGreen
        } else {
            "TUNNEL CONNECTED • INTERNET UNVERIFIED" to ConnectingAmber
        }
        is VpnState.TunnelEstablished -> "TUNNEL ESTABLISHED • VERIFYING" to ConnectingAmber
        is VpnState.Connecting -> "CONNECTING..." to ConnectingAmber
        is VpnState.StartingEngine -> "STARTING ENGINE" to ConnectingAmber
        is VpnState.Validating -> "VALIDATING" to ConnectingAmber
        is VpnState.Reconnecting -> "RECONNECTING (${state.attempt}/${state.maxAttempts})" to ConnectingAmber
        is VpnState.Stopping -> "DISCONNECTING..." to ConnectingAmber
        is VpnState.Error -> "CONNECTION FAILED" to DisconnectedRed
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
    val (buttonColor, glowColor) = when (state) {
        is VpnState.Connected -> if (state.isInternetVerified) {
            ConnectedGreen to ConnectedGreen.copy(alpha = 0.3f)
        } else {
            ConnectingAmber to ConnectingAmber.copy(alpha = 0.32f)
        }
        is VpnState.TunnelEstablished, is VpnState.Connecting, is VpnState.StartingEngine, is VpnState.Validating, is VpnState.Reconnecting, is VpnState.Stopping ->
            ConnectingAmber to ConnectingAmber.copy(alpha = 0.35f)
        is VpnState.Error -> DisconnectedRed to DisconnectedRed.copy(alpha = 0.25f)
        else -> CyanPrimaryDark to CyanPrimaryDark.copy(alpha = 0.25f)
    }

    val liquidFill = when {
        state.isConnected -> 0.48f
        state.isBusy -> 0.36f
        else -> 0.24f
    }

    val animatedColor by animateColorAsState(targetValue = buttonColor, label = "buttonColor")

    Box(
        modifier = modifier
            .size(190.dp)
            .testTag("connect_button_container"),
        contentAlignment = Alignment.Center
    ) {
        // Outer pulsing ring ONLY allocated when state.isBusy is true (0 FPS when idle or connected)
        if (state.isBusy) {
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

        // Main Button Surface with interactive zero-drain liquid wave inside the orb
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
            InteractiveLiquidLayer(
                liquidColor = animatedColor,
                baseFillFraction = liquidFill,
                stateKey = state::class.simpleName,
                modifier = Modifier.fillMaxSize()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(16.dp),
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
                            state is VpnState.Stopping -> "STOPPING"
                            state.isBusy -> "CONNECTING"
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
