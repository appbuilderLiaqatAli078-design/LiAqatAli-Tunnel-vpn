package com.example.ui.screens

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.model.VpnProfile
import com.example.parser.ConfigParser
import com.example.parser.ParseResult
import com.example.ui.components.GlassCard
import com.example.ui.theme.ConnectedGreen
import com.example.ui.theme.CyanPrimaryDark
import com.example.ui.theme.DisconnectedRed
import com.example.ui.viewmodel.VpnViewModel

@Composable
fun ImportScreen(
    viewModel: VpnViewModel,
    onImportSuccess: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var inputText by remember { mutableStateOf("") }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var isSuccess by remember { mutableStateOf(false) }
    var parsedProfile by remember { mutableStateOf<VpnProfile?>(null) }

    fun validateAndParse(text: String) {
        val result = ConfigParser.parse(text)
        when (result) {
            is ParseResult.Success -> {
                isSuccess = true
                parsedProfile = result.profile
                statusMessage = "Valid ${result.profile.protocol.displayName} configuration"
            }
            is ParseResult.Failure -> {
                isSuccess = false
                parsedProfile = null
                statusMessage = result.reason
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Import Configuration",
            style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
            color = MaterialTheme.colorScheme.onBackground
        )

        Text(
            text = "Import configs from clipboard or paste standard vmess://, vless://, trojan://, ss://, ssh://, or Xray JSON configurations.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Paste from clipboard button
        OutlinedButton(
            onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = clipboard.primaryClip
                if (clip != null && clip.itemCount > 0) {
                    val pasted = clip.getItemAt(0).text?.toString() ?: ""
                    inputText = pasted
                    validateAndParse(pasted)
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("paste_clipboard_button")
        ) {
            Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Paste from Clipboard")
        }

        // Configuration Text Area
        OutlinedTextField(
            value = inputText,
            onValueChange = {
                inputText = it
                if (it.isNotBlank()) {
                    validateAndParse(it)
                } else {
                    statusMessage = null
                    parsedProfile = null
                }
            },
            label = { Text("Configuration String or JSON") },
            placeholder = { Text("vmess://..., vless://..., trojan://..., ssh://..., or {\"outbounds\": ...}") },
            modifier = Modifier
                .fillMaxWidth()
                .height(180.dp)
                .testTag("import_text_input"),
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            shape = RoundedCornerShape(16.dp),
            maxLines = 10
        )

        // Validation Result Banner
        AnimatedVisibility(visible = statusMessage != null) {
            GlassCard(
                modifier = Modifier.fillMaxWidth(),
                cornerRadius = 16.dp,
                borderColor = if (isSuccess) ConnectedGreen else DisconnectedRed
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = if (isSuccess) Icons.Default.CheckCircle else Icons.Default.ErrorOutline,
                        contentDescription = null,
                        tint = if (isSuccess) ConnectedGreen else DisconnectedRed,
                        modifier = Modifier.size(24.dp)
                    )
                    Column {
                        Text(
                            text = if (isSuccess) "Configuration Valid" else "Validation Error",
                            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Bold),
                            color = if (isSuccess) ConnectedGreen else DisconnectedRed
                        )
                        Text(
                            text = statusMessage ?: "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        if (parsedProfile != null) {
                            Text(
                                text = "Target: ${parsedProfile?.server}:${parsedProfile?.port} (${parsedProfile?.protocol?.displayName})",
                                style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.SemiBold),
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            }
        }

        // Example Chips
        Text(
            text = "Supported Formats:",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            SuggestionChip(onClick = {
                inputText = "vless://d342d110-d4a3-4513-bfa6-07a5e0f0ff37@example.com:443?security=tls&type=ws&sni=example.com#VLESS-Demo"
                validateAndParse(inputText)
            }, label = { Text("VLESS") })

            SuggestionChip(onClick = {
                inputText = "trojan://password123@secure.vpn.org:443?sni=secure.vpn.org#Trojan-Demo"
                validateAndParse(inputText)
            }, label = { Text("Trojan") })

            SuggestionChip(onClick = {
                inputText = "ssh://root:secret@128.199.192.1:22#SSH-Demo"
                validateAndParse(inputText)
            }, label = { Text("SSH") })
        }

        Spacer(modifier = Modifier.weight(1f))

        // Save Button
        Button(
            onClick = {
                parsedProfile?.let { profile ->
                    viewModel.saveProfile(profile)
                    viewModel.selectProfile(profile)
                    onImportSuccess()
                }
            },
            enabled = isSuccess && parsedProfile != null,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp)
                .testTag("save_imported_button"),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = CyanPrimaryDark,
                contentColor = Color(0xFF00363E)
            )
        ) {
            Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Save Profile", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold))
        }
    }
}
