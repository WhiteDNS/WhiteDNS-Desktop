package com.tunnelcheck.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.ui.AppLanguage
import com.tunnelcheck.app.ui.AppSettings
import com.tunnelcheck.app.ui.AppThemeMode
import com.tunnelcheck.app.ui.RootUiState

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun SettingsScreen(state: RootUiState, onSettingsChange: (AppSettings) -> Unit) {
    val text = state.text
    ScreenShell(text.settings, state, scrollable = true) {
        SettingsCard(title = text.appearance) {
            Text(text.theme, style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ThemeChip(text.system, state.settings.themeMode == AppThemeMode.FollowSystem) {
                    onSettingsChange(state.settings.copy(themeMode = AppThemeMode.FollowSystem))
                }
                ThemeChip(text.light, state.settings.themeMode == AppThemeMode.Light) {
                    onSettingsChange(state.settings.copy(themeMode = AppThemeMode.Light))
                }
                ThemeChip(text.dark, state.settings.themeMode == AppThemeMode.Dark) {
                    onSettingsChange(state.settings.copy(themeMode = AppThemeMode.Dark))
                }
            }
            Text(text.language, style = MaterialTheme.typography.labelLarge)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ThemeChip(text.english, state.settings.language == AppLanguage.English) {
                    onSettingsChange(state.settings.copy(language = AppLanguage.English))
                }
                ThemeChip(text.farsi, state.settings.language == AppLanguage.Farsi) {
                    onSettingsChange(state.settings.copy(language = AppLanguage.Farsi))
                }
            }
        }

        SettingsCard(title = text.scanDefaults) {
            SettingRow(text.udpProbe, state.settings.enableUdp) { onSettingsChange(state.settings.copy(enableUdp = it)) }
            SettingRow(text.quicProbe, state.settings.enableQuic) { onSettingsChange(state.settings.copy(enableQuic = it)) }
            SettingRow(text.dnsProbe, state.settings.enableDns) { onSettingsChange(state.settings.copy(enableDns = it)) }
            SettingRow(text.wsProbe, state.settings.enableWebSocket) { onSettingsChange(state.settings.copy(enableWebSocket = it)) }
            SettingRow(text.allowInsecureCert, state.settings.allowInsecureCert) { onSettingsChange(state.settings.copy(allowInsecureCert = it)) }
            StepperRow(
                label = text.retries,
                value = state.settings.retries,
                suffix = "",
                onMinus = { onSettingsChange(state.settings.copy(retries = state.settings.retries - 1)) },
                onPlus = { onSettingsChange(state.settings.copy(retries = state.settings.retries + 1)) }
            )
            StepperRow(
                label = text.timeout,
                value = state.settings.timeoutMillis,
                suffix = " ms",
                onMinus = { onSettingsChange(state.settings.copy(timeoutMillis = state.settings.timeoutMillis - 500)) },
                onPlus = { onSettingsChange(state.settings.copy(timeoutMillis = state.settings.timeoutMillis + 500)) }
            )
        }

        SettingsCard(title = text.privacy) {
            SettingRow(text.localOnly, true, enabled = false) {}
            Text(text.noUpload, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        Text(
            text = "Made with ❤️ by WhisperInHeaven",
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp, bottom = 18.dp),
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
            content()
        }
    }
}

@Composable
private fun ThemeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    AssistChip(onClick = onClick, label = { Text(label) }, enabled = !selected)
}

@Composable
private fun SettingRow(label: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

@Composable
private fun StepperRow(label: String, value: Int, suffix: String, onMinus: () -> Unit, onPlus: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = onMinus) { Text("-") }
            Text("$value$suffix", style = MaterialTheme.typography.labelLarge)
            OutlinedButton(onClick = onPlus) { Text("+") }
        }
    }
}
