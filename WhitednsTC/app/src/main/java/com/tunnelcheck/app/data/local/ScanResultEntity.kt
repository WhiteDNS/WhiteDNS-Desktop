package com.tunnelcheck.app.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.tunnelcheck.app.domain.model.EndpointResult
import com.tunnelcheck.app.domain.model.ScanMode

@Entity(tableName = "scan_results")
data class ScanResultEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val endpoint: String,
    val host: String,
    val port: Int,
    val tcp: Boolean,
    val tls: Boolean,
    val http: Boolean,
    val webSocket: Boolean,
    val udp: Boolean,
    val quic: Boolean,
    val dns: Boolean,
    val rttMs: Long,
    val jitterMs: Long,
    val packetLoss: Double,
    val stability: Double,
    val score: Int,
    val grade: String,
    val classification: String,
    val confidence: Double,
    val falsePositive: Boolean,
    val rawJson: String,
    val scanMode: String,
    val scannedAt: Long,
    val notes: String,
    val favorite: Boolean,
    val tagsCsv: String
) {
    fun toDomain() = EndpointResult(
        id = id,
        endpoint = endpoint,
        host = host,
        port = port,
        tcp = tcp,
        tls = tls,
        http = http,
        webSocket = webSocket,
        udp = udp,
        quic = quic,
        dns = dns,
        rttMs = rttMs,
        jitterMs = jitterMs,
        packetLoss = packetLoss,
        stability = stability,
        score = score,
        grade = grade,
        classification = classification,
        confidence = confidence,
        falsePositive = falsePositive,
        rawJson = rawJson,
        scanMode = runCatching { ScanMode.valueOf(scanMode) }.getOrDefault(ScanMode.Quick),
        scannedAt = scannedAt,
        notes = notes,
        favorite = favorite,
        tags = tagsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    )
}

fun EndpointResult.toEntity() = ScanResultEntity(
    id = id,
    endpoint = endpoint,
    host = host,
    port = port,
    tcp = tcp,
    tls = tls,
    http = http,
    webSocket = webSocket,
    udp = udp,
    quic = quic,
    dns = dns,
    rttMs = rttMs,
    jitterMs = jitterMs,
    packetLoss = packetLoss,
    stability = stability,
    score = score,
    grade = grade,
    classification = classification,
    confidence = confidence,
    falsePositive = falsePositive,
    rawJson = rawJson,
    scanMode = scanMode.name,
    scannedAt = scannedAt,
    notes = notes,
    favorite = favorite,
    tagsCsv = tags.joinToString(",")
)
