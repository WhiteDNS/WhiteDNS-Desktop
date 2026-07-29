package com.tunnelcheck.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.ui.RootUiState

@Composable
fun QuickTestScreen(state: RootUiState, onScan: (String, String) -> Unit, onCancel: () -> Unit) {
    var host by remember { mutableStateOf("1.1.1.1") }
    var ports by remember { mutableStateOf("443,8443,2053") }
    ScreenShell(state.text.quickTest, state) {
        OutlinedTextField(host, { host = it }, modifier = Modifier.fillMaxWidth(), label = { Text(state.text.ipOrDomain) }, singleLine = true)
        OutlinedTextField(ports, { ports = it }, modifier = Modifier.fillMaxWidth(), label = { Text(state.text.ports) }, singleLine = true)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(onClick = { onScan(host, ports) }, enabled = !state.activeScan) {
                Icon(Icons.Default.PlayArrow, contentDescription = null)
                Text(state.text.run)
            }
            Button(onClick = onCancel, enabled = state.activeScan) {
                Text(state.text.cancel)
            }
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(state.quickResults.take(20), key = { it.id }) { ResultCard(it, state.text) }
        }
    }
}
