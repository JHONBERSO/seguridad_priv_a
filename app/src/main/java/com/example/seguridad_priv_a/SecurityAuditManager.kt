package com.example.seguridad_priv_a.security

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.concurrent.ConcurrentHashMap

class SecurityAuditManager(private val context: Context) {

    private val accessLog = mutableListOf<AccessEvent>()
    private val lastOperationTimestamps = ConcurrentHashMap<String, MutableList<Long>>()
    private val keyPair: KeyPair by lazy { generateKeyPair() }

    // Configuración
    private val rateLimitWindowMs = 60_000L // 1 minuto
    private val rateLimitThreshold = 5       // máx. 5 solicitudes
    private val suspiciousIntervalMs = 3000L // múltiples solicitudes en 3 seg = sospechoso

    // === Public Methods ===

    fun logEvent(eventType: String, details: String) {
        val timestamp = System.currentTimeMillis()
        val event = AccessEvent(timestamp, eventType, details)
        accessLog.add(event)

        if (isSuspicious(eventType, timestamp)) {
            triggerAlert("Acceso sospechoso: $eventType")
        }

        if (isRateLimited(eventType, timestamp)) {
            triggerAlert("Rate limit excedido: $eventType")
        }
    }

    fun exportSignedJsonLogs(outputFile: File): Boolean {
        val jsonArray = JSONArray()
        for (event in accessLog) {
            val json = JSONObject()
            json.put("timestamp", event.timestamp)
            json.put("eventType", event.type)
            json.put("details", event.details)
            jsonArray.put(json)
        }

        val jsonString = jsonArray.toString()
        val signature = signData(jsonString.toByteArray())
        val signedJson = JSONObject().apply {
            put("logs", jsonArray)
            put("signature", signature)
        }

        return try {
            outputFile.writeText(signedJson.toString())
            true
        } catch (e: Exception) {
            false
        }
    }

    // === Internal Logic ===

    private fun isSuspicious(eventType: String, currentTime: Long): Boolean {
        val timestamps = lastOperationTimestamps.getOrPut(eventType) { mutableListOf() }
        timestamps.add(currentTime)

        // Limpiar timestamps viejos
        timestamps.removeIf { it < currentTime - suspiciousIntervalMs }

        return timestamps.size >= 3 // más de 3 eventos del mismo tipo en <3 seg
    }

    private fun isRateLimited(eventType: String, currentTime: Long): Boolean {
        val timestamps = lastOperationTimestamps.getOrPut(eventType) { mutableListOf() }
        timestamps.add(currentTime)

        // Limpiar ventanas anteriores
        timestamps.removeIf { it < currentTime - rateLimitWindowMs }

        return timestamps.size > rateLimitThreshold
    }

    private fun triggerAlert(message: String) {
        // Aquí podrías mostrar un Toast, enviar una notificación, o registrar en logs
        android.util.Log.w("SecurityAudit", "⚠️ ALERTA: $message")
    }

    private fun generateKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(2048)
        return keyGen.generateKeyPair()
    }

    private fun signData(data: ByteArray): String {
        val privateKey = keyPair.private
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(data)
        val signed = signature.sign()
        return Base64.encodeToString(signed, Base64.NO_WRAP)
    }

    // === Data Class ===

    private data class AccessEvent(
        val timestamp: Long,
        val type: String,
        val details: String
    )
}
