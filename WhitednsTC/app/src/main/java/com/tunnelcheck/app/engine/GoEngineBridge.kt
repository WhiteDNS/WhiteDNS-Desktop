package com.tunnelcheck.app.engine

import com.tunnelcheck.app.domain.model.EndpointInput
import com.tunnelcheck.app.domain.model.EndpointResult
import com.tunnelcheck.app.domain.model.ScanOptions
import org.json.JSONArray
import org.json.JSONObject
import tunnelengine.Tunnelengine
import javax.inject.Inject
import javax.inject.Singleton

interface TunnelEngine {
    suspend fun scan(endpoint: EndpointInput, options: ScanOptions): EndpointResult
    suspend fun scanBatch(endpoints: List<EndpointInput>, options: ScanOptions): List<EndpointResult>
}

@Singleton
class GoEngineBridge @Inject constructor() : TunnelEngine {
    override suspend fun scan(endpoint: EndpointInput, options: ScanOptions): EndpointResult {
        val request = endpoint.toRequestJson(options).toString()
        val raw = Tunnelengine.scanEndpoint(request)
        return parseResult(raw)
    }

    override suspend fun scanBatch(endpoints: List<EndpointInput>, options: ScanOptions): List<EndpointResult> {
        val array = JSONArray()
        endpoints.forEach { array.put(it.toRequestJson(options)) }
        val request = JSONObject()
            .put("endpoints", array)
            .put("adaptiveLimit", 48)
            .put("timeoutMillis", options.timeoutMillis)
            .put("defaultRetries", options.retries)
            .toString()
        val raw = Tunnelengine.scanBatch(request)
        val json = JSONObject(raw)
        val results = json.optJSONArray("results") ?: JSONArray()
        return (0 until results.length()).map { parseResult(results.getJSONObject(it).toString()) }
    }

    private fun EndpointInput.toRequestJson(options: ScanOptions) = JSONObject()
        .put("host", host)
        .put("port", port)
        .put("sni", sni ?: host)
        .put("timeoutMillis", options.timeoutMillis)
        .put("retries", options.retries)
        .put("enableUdp", options.enableUdp)
        .put("enableQuic", options.enableQuic)
        .put("enableDns", options.enableDns)
        .put("enableWebSocket", options.enableWebSocket)
        .put("allowInsecureCert", options.allowInsecureCert)
}

fun parseResult(rawJson: String): EndpointResult {
    val json = JSONObject(rawJson)
    val tcp = json.optJSONObject("tcp") ?: JSONObject()
    val tls = json.optJSONObject("tls") ?: JSONObject()
    val http = json.optJSONObject("http") ?: JSONObject()
    val ws = json.optJSONObject("webSocket") ?: JSONObject()
    val udp = json.optJSONObject("udp") ?: JSONObject()
    val quic = json.optJSONObject("quic") ?: JSONObject()
    val dns = json.optJSONObject("dns") ?: JSONObject()
    val metrics = json.optJSONObject("metrics") ?: JSONObject()
    val score = json.optJSONObject("score") ?: JSONObject()
    return EndpointResult(
        endpoint = json.optString("endpoint"),
        host = json.optString("host"),
        port = json.optInt("port"),
        tcp = tcp.optBoolean("success"),
        tls = tls.optBoolean("success"),
        http = http.optBoolean("success"),
        webSocket = ws.optBoolean("success"),
        udp = udp.optBoolean("reachable"),
        quic = quic.optBoolean("success"),
        dns = dns.optBoolean("udpResponsive") || dns.optBoolean("tcpResponsive"),
        rttMs = metrics.optLong("rttMs"),
        jitterMs = metrics.optLong("jitterMs"),
        packetLoss = metrics.optDouble("packetLossEstimate"),
        stability = metrics.optDouble("stabilityPercent"),
        score = score.optInt("numeric"),
        grade = score.optString("grade", "F"),
        classification = score.optString("classification", "Blocked"),
        confidence = score.optDouble("confidence"),
        falsePositive = score.optBoolean("falsePositive"),
        rawJson = rawJson
    )
}
