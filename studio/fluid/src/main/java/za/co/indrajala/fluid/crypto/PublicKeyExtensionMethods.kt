package za.co.indrajala.fluid.crypto

import java.security.PublicKey

fun PublicKey.describe() : String =
    listOf(
        "algorithm: ${this.algorithm}",
        "format: ${this.format}",
        "key in ASN.1 DER: ${this.encoded.toHex()}"
    ).joinToString("\n")