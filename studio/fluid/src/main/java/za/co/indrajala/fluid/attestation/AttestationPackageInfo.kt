package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import za.co.indrajala.fluid.bit.hexToUBytes
import za.co.indrajala.fluid.bit.toHex
import za.co.indrajala.fluid.crypto.bouncy_castle.getBytes
import za.co.indrajala.fluid.crypto.bouncy_castle.getInt

class AttestationPackageInfo(
    private val seq: ASN1Sequence
) {
    class Indices {
        companion object {
            val PACKAGE_NAME = 0
            val PACKAGE_VERSION = 1
        }
    }

    private fun getInteger(index: Int): Int? =
        (seq.getObjectAt(index) as ASN1Integer).getInt()

    fun getHex(index: Int): String? =
        seq.getObjectAt(index).getBytes().toHex()

    val packageName: String?
        get() = getHex(Indices.PACKAGE_NAME)

    val version: Int?
        get() = getInteger(Indices.PACKAGE_VERSION)

    fun summary() = listOf(
        Pair("Package Name", packageName?.hexToUBytes()?.toByteArray()?.decodeToString()),
        Pair("Version", version?.toString())
    )
}