package com.tunnelcheck.app.ui

import android.content.Context
import androidx.core.content.edit
import com.tunnelcheck.app.domain.model.ScanOptions

enum class AppThemeMode { FollowSystem, Light, Dark }
enum class AppLanguage { English, Farsi }

data class AppSettings(
    val themeMode: AppThemeMode = AppThemeMode.Dark,
    val language: AppLanguage = AppLanguage.English,
    val enableUdp: Boolean = true,
    val enableQuic: Boolean = true,
    val enableDns: Boolean = true,
    val enableWebSocket: Boolean = true,
    val allowInsecureCert: Boolean = false,
    val retries: Int = 3,
    val timeoutMillis: Int = 3500
) {
    fun scanOptions() = ScanOptions(
        retries = retries,
        timeoutMillis = timeoutMillis,
        enableUdp = enableUdp,
        enableQuic = enableQuic,
        enableDns = enableDns,
        enableWebSocket = enableWebSocket,
        allowInsecureCert = allowInsecureCert
    )
}

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences("tunnelcheck_settings", Context.MODE_PRIVATE)

    fun load() = AppSettings(
        themeMode = runCatching {
            val stored = prefs.getString("themeMode", AppThemeMode.Dark.name) ?: AppThemeMode.Dark.name
            if (stored == "System") AppThemeMode.FollowSystem else enumValueOf(stored)
        }.getOrDefault(AppThemeMode.Dark),
        language = runCatching {
            enumValueOf<AppLanguage>(prefs.getString("language", AppLanguage.English.name) ?: AppLanguage.English.name)
        }.getOrDefault(AppLanguage.English),
        enableUdp = prefs.getBoolean("enableUdp", true),
        enableQuic = prefs.getBoolean("enableQuic", true),
        enableDns = prefs.getBoolean("enableDns", true),
        enableWebSocket = prefs.getBoolean("enableWebSocket", true),
        allowInsecureCert = prefs.getBoolean("allowInsecureCert", false),
        retries = prefs.getInt("retries", 3),
        timeoutMillis = prefs.getInt("timeoutMillis", 3500)
    )

    fun save(settings: AppSettings) {
        prefs.edit {
            putString("themeMode", settings.themeMode.name)
            putString("language", settings.language.name)
            putBoolean("enableUdp", settings.enableUdp)
            putBoolean("enableQuic", settings.enableQuic)
            putBoolean("enableDns", settings.enableDns)
            putBoolean("enableWebSocket", settings.enableWebSocket)
            putBoolean("allowInsecureCert", settings.allowInsecureCert)
            putInt("retries", settings.retries)
            putInt("timeoutMillis", settings.timeoutMillis)
        }
    }
}
