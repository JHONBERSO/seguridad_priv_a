package com.example.seguridad_priv_a.model

data class AnonymizedData(
    val groupId: Int,
    val quasiIdentifiers: Map<String, Any>,
    val sensitive: String
)
