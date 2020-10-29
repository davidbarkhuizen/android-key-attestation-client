package za.co.indrajala.fluid.crypto

import za.co.indrajala.fluid.ubyte.toHex
import java.security.PublicKey

fun PublicKey.summary() : String =
    listOf(
        "algorithm: ${this.algorithm}",
        "format: ${this.format}",
        "key in ASN.1 DER: ${this.encoded.toHex()}"
    ).joinToString("\n")