package com.example.seguridad_priv_a.model

enum class DataType {
    EMAIL, PHONE, NAME, DNI
}

data class MaskingPolicy(
    val type: DataType,
    val maskChar: Char = '*',
    val visiblePrefix: Int = 2
)
