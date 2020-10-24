package za.co.indrajala.fluid.model

data class PublicKeyCert(
    val asn1hex: String? = null,
    val chain: List<String>? = null
)