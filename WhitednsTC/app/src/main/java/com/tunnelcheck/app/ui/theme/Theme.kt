package com.tunnelcheck.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.tunnelcheck.app.ui.AppThemeMode

private val Dark = darkColorScheme(
    primary = Color(0xFF22D3EE),
    secondary = Color(0xFF34D399),
    tertiary = Color(0xFFF59E0B),
    background = Color(0xFF071018),
    surface = Color(0xFF0E1A24),
    surfaceVariant = Color(0xFF172635),
    onPrimary = Color(0xFF001017),
    onSecondary = Color(0xFF00140D),
    onBackground = Color(0xFFE6F6FF),
    onSurface = Color(0xFFE6F6FF)
)

private val Light = lightColorScheme(
    primary = Color(0xFF006A7A),
    secondary = Color(0xFF006C4F),
    tertiary = Color(0xFF8A5A00),
    background = Color(0xFFF8FBFD),
    surface = Color.White,
    surfaceVariant = Color(0xFFE7EEF4)
)

@Composable
fun TunnelCheckTheme(themeMode: AppThemeMode = AppThemeMode.FollowSystem, content: @Composable () -> Unit) {
    val darkTheme = when (themeMode) {
        AppThemeMode.FollowSystem -> isSystemInDarkTheme()
        AppThemeMode.Light -> false
        AppThemeMode.Dark -> true
    }
    val scheme: ColorScheme = if (darkTheme) Dark else Light
    MaterialTheme(colorScheme = scheme, typography = TunnelTypography, content = content)
}
