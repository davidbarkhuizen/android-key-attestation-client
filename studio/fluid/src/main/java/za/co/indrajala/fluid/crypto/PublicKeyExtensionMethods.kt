package za.co.indrajala.fluid.crypto

import za.co.indrajala.fluid.util.toHexString
import java.security.PublicKey

fun PublicKey.describe() : String =
    listOf(
        "algorithm: ${this.algorithm}",
        "format: ${this.format}",
        "key in ASN.1 DER: ${this.encoded.toHexString()}"
    ).joinToString("\n")