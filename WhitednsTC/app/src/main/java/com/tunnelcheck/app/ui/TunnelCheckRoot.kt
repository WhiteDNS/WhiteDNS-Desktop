package com.tunnelcheck.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.tunnelcheck.app.ui.theme.TunnelCheckTheme
import com.tunnelcheck.app.ui.screens.BulkScanScreen
import com.tunnelcheck.app.ui.screens.DashboardScreen
import com.tunnelcheck.app.ui.screens.ExportScreen
import com.tunnelcheck.app.ui.screens.HistoryScreen
import com.tunnelcheck.app.ui.screens.QuickTestScreen
import com.tunnelcheck.app.ui.screens.SettingsScreen

private enum class Tab { Dashboard, Quick, Bulk, History, Export, Settings }

@Composable
fun TunnelCheckRoot(viewModel: RootViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsState()
    var tab by remember { mutableStateOf(Tab.Dashboard) }
    TunnelCheckTheme(themeMode = state.settings.themeMode) {
        Scaffold(
            bottomBar = {
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                    tonalElevation = 8.dp
                ) {
                    item(Tab.Dashboard, tab, { tab = it }, Icons.Default.Home, state.text.dashboard)
                    item(Tab.Quick, tab, { tab = it }, Icons.Default.PlayArrow, state.text.quick)
                    item(Tab.Bulk, tab, { tab = it }, Icons.Default.List, state.text.bulk)
                    item(Tab.History, tab, { tab = it }, Icons.Default.List, state.text.history)
                    item(Tab.Export, tab, { tab = it }, Icons.Default.List, state.text.export)
                    item(Tab.Settings, tab, { tab = it }, Icons.Default.Settings, state.text.settings)
                }
            }
        ) { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background)
                    .padding(padding)
            ) {
                when (tab) {
                    Tab.Dashboard -> DashboardScreen(state, viewModel::setFilter)
                    Tab.Quick -> QuickTestScreen(state, viewModel::quickScan, viewModel::cancelScan)
                    Tab.Bulk -> BulkScanScreen(state, viewModel::bulkScan, viewModel::cancelScan)
                    Tab.History -> HistoryScreen(state, viewModel::setFilter, viewModel::clear)
                    Tab.Export -> ExportScreen(state, viewModel::export)
                    Tab.Settings -> SettingsScreen(state, viewModel::updateSettings)
                }
            }
        }
    }
}

@Composable
private fun RowScope.item(
    target: Tab,
    current: Tab,
    onSelect: (Tab) -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String
) {
    NavigationBarItem(
        selected = current == target,
        onClick = { onSelect(target) },
        icon = { Icon(icon, contentDescription = label) },
        label = { Text(label, maxLines = 1) },
        colors = NavigationBarItemDefaults.colors(
            selectedIconColor = MaterialTheme.colorScheme.onPrimary,
            selectedTextColor = MaterialTheme.colorScheme.primary,
            indicatorColor = MaterialTheme.colorScheme.primary,
            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
            unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant
        )
    )
}
