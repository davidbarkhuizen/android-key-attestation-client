package za.co.indrajala.fluid.crypto.java

import za.co.indrajala.fluid.bit.toHex
import java.security.PublicKey

fun PublicKey.summary() : String =
    listOf(
        "algorithm: ${this.algorithm}",
        "format: ${this.format}",
        "key in ASN.1 DER: ${this.encoded.toHex()}"
    ).joinToString("\n")