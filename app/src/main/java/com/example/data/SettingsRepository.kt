package com.example.data

import android.content.Context
import android.content.SharedPreferences
import com.example.model.AppSettings
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class SettingsRepository(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("ctp_settings", Context.MODE_PRIVATE)

    private val _settings = MutableStateFlow(loadSettings())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    private fun loadSettings(): AppSettings {
        return AppSettings(
            theme = prefs.getString("theme", "system") ?: "system",
            autoReconnect = prefs.getBoolean("auto_reconnect", true),
            maxRetries = prefs.getInt("max_retries", 5),
            proMode = prefs.getBoolean("pro_mode", true),
            defaultDns = prefs.getString("default_dns", "1.1.1.1") ?: "1.1.1.1",
            customDns = prefs.getString("custom_dns", "8.8.8.8") ?: "8.8.8.8",
            blockIpv6ByDefault = prefs.getBoolean("block_ipv6", true),
            bypassLan = prefs.getBoolean("bypass_lan", true)
        )
    }

    fun updateSettings(settings: AppSettings) {
        prefs.edit().apply {
            putString("theme", settings.theme)
            putBoolean("auto_reconnect", settings.autoReconnect)
            putInt("max_retries", settings.maxRetries)
            putBoolean("pro_mode", settings.proMode)
            putString("default_dns", settings.defaultDns)
            putString("custom_dns", settings.customDns)
            putBoolean("block_ipv6", settings.blockIpv6ByDefault)
            putBoolean("bypass_lan", settings.bypassLan)
            apply()
        }
        _settings.value = settings
    }
}
