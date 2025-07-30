package com.example.seguridad_priv_a.security

import com.example.seguridad_priv_a.model.*
import kotlin.math.*
import kotlin.random.Random

class AdvancedAnonymizer {

    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData> {
        val grouped = data.groupBy { "${it.age / 10}_${it.gender}_${it.zipCode.take(3)}" }
        val anonymized = mutableListOf<AnonymizedData>()
        var groupId = 1

        for ((_, group) in grouped) {
            if (group.size >= k && hasLDiversity(group, "disease", 2)) {
                for (record in group) {
                    anonymized.add(
                        AnonymizedData(
                            groupId,
                            mapOf(
                                "age" to "${(record.age / 10) * 10}–${(record.age / 10) * 10 + 9}",
                                "gender" to record.gender,
                                "zip" to record.zipCode.take(3) + "**"
                            ),
                            record.disease
                        )
                    )
                }
                groupId++
            }
        }
        return anonymized
    }

    private fun hasLDiversity(group: List<PersonalData>, field: String, l: Int): Boolean {
        val diversity = group.map { it.disease }.toSet()
        return diversity.size >= l
    }

    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData {
        val noise = laplaceNoise(1.0, epsilon)
        return NumericData(data.label, data.value + noise)
    }

    private fun laplaceNoise(sensitivity: Double, epsilon: Double): Double {
        val u = Random.nextDouble() - 0.5
        return -sensitivity / epsilon * sign(u) * ln(1 - 2 * abs(u))
    }

    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any {
        val value = data.toString()
        return when (maskingPolicy.type) {
            DataType.EMAIL -> {
                val parts = value.split("@")
                val prefix = parts[0].take(maskingPolicy.visiblePrefix)
                "$prefix${"*".repeat(parts[0].length - maskingPolicy.visiblePrefix)}@${parts[1]}"
            }
            DataType.PHONE -> "*".repeat(value.length - 4) + value.takeLast(4)
            DataType.DNI -> value.take(2) + "*".repeat(value.length - 4) + value.takeLast(2)
            DataType.NAME -> value.first() + "."
        }
    }

    fun enforceRetentionPolicy(storage: MutableMap<String, Long>, maxDays: Int) {
        val now = System.currentTimeMillis()
        val expired = storage.filterValues {
            now - it > maxDays * 24 * 60 * 60 * 1000
        }.keys
        for (key in expired) storage.remove(key)
    }
}
