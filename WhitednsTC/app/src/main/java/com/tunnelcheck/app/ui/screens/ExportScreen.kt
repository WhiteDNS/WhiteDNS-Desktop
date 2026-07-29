package com.tunnelcheck.app.ui.screens

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.tunnelcheck.app.ui.RootUiState

@Composable
fun ExportScreen(state: RootUiState, onExport: (String) -> Unit) {
    ScreenShell(state.text.exportCenter, state) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(onClick = { onExport("json") }) { Text("JSON") }
            Button(onClick = { onExport("csv") }) { Text("CSV") }
            Button(onClick = { onExport("txt") }) { Text("TXT") }
        }
        OutlinedTextField(
            value = state.exportText,
            onValueChange = {},
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            minLines = 12,
            readOnly = true,
            label = { Text(state.text.exportOutput) }
        )
    }
}
