package com.tunnelcheck.app.data.export

import com.tunnelcheck.app.domain.model.EndpointInput
import org.json.JSONArray
import org.json.JSONObject

object EndpointParser {
    fun parse(text: String): List<EndpointInput> {
        val trimmed = text.trim()
        if (trimmed.startsWith("[") || trimmed.startsWith("{")) return parseJson(trimmed)
        return trimmed.lineSequence()
            .flatMap { line -> parseLine(line).asSequence() }
            .distinctBy { it.key }
            .toList()
    }

    private fun parseJson(text: String): List<EndpointInput> {
        val array = if (text.startsWith("[")) JSONArray(text) else JSONObject(text).optJSONArray("endpoints") ?: JSONArray()
        return (0 until array.length()).mapNotNull { i ->
            when (val item = array.get(i)) {
                is String -> parseLine(item).firstOrNull()
                is JSONObject -> EndpointInput(item.optString("host"), item.optInt("port"), item.optString("sni").ifBlank { null })
                else -> null
            }
        }.filter { it.host.isNotBlank() && it.port in 1..65535 }
    }

    private fun parseLine(raw: String): List<EndpointInput> {
        val line = raw.substringBefore('#').trim().trim(',')
        if (line.isBlank()) return emptyList()
        val csv = line.split(',').map { it.trim() }
        if (csv.size >= 2 && csv[1].toIntOrNull() != null) {
            val port = csv[1].toInt()
            return if (csv[0].isNotBlank() && port in 1..65535) listOf(EndpointInput(csv[0], port)) else emptyList()
        }
        val parts = line.split(',', ';').map { it.trim() }.filter { it.isNotBlank() }
        return parts.mapNotNull { token ->
            val host = token.substringBeforeLast(':', "")
            val port = token.substringAfterLast(':', "").toIntOrNull()
            if (host.isBlank() || port == null || port !in 1..65535) null else EndpointInput(host, port)
        }
    }
}
