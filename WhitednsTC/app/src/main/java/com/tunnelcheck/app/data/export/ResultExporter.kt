package com.tunnelcheck.app.data.export

import com.tunnelcheck.app.domain.model.EndpointResult
import org.json.JSONArray
import org.json.JSONObject
import javax.inject.Inject

class ResultExporter @Inject constructor() {
    fun txt(results: List<EndpointResult>) = results.joinToString("\n") { "${it.endpoint} ${it.grade} ${it.classification} rtt=${it.rttMs}ms stability=${it.stability}%" }

    fun csv(results: List<EndpointResult>): String = buildString {
        appendLine("endpoint,tcp,tls,ws,udp,quic,dns,rtt_ms,jitter_ms,packet_loss,stability,score,grade,classification,confidence")
        results.forEach {
            appendLine(listOf(it.endpoint, it.tcp, it.tls, it.webSocket, it.udp, it.quic, it.dns, it.rttMs, it.jitterMs, it.packetLoss, it.stability, it.score, it.grade, it.classification, it.confidence).joinToString(","))
        }
    }

    fun json(results: List<EndpointResult>): String {
        val array = JSONArray()
        results.forEach {
            array.put(JSONObject()
                .put("endpoint", it.endpoint)
                .put("tcp", it.tcp)
                .put("tls", it.tls)
                .put("ws", it.webSocket)
                .put("udp", it.udp)
                .put("quic", it.quic)
                .put("dns", it.dns)
                .put("rtt", it.rttMs)
                .put("jitter", it.jitterMs)
                .put("packetLoss", it.packetLoss)
                .put("stability", it.stability)
                .put("score", it.grade)
                .put("classification", it.classification)
                .put("confidence", it.confidence))
        }
        return array.toString(2)
    }
}
