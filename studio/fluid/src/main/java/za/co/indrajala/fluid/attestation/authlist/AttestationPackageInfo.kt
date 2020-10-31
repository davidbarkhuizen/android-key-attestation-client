package za.co.indrajala.fluid.attestation.authlist

import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import za.co.indrajala.fluid.asn1.getBytes
import za.co.indrajala.fluid.asn1.getInt
import za.co.indrajala.fluid.ubyte.toHex

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
        Pair("Package Name", packageName),
        Pair("Version", version?.toString())
    )
}