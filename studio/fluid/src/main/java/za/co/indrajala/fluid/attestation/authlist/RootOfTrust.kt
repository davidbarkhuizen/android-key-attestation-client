package za.co.indrajala.fluid.attestation.authlist

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.asn1.getBoolean
import za.co.indrajala.fluid.asn1.getBytes
import za.co.indrajala.fluid.asn1.getInt
import za.co.indrajala.fluid.ubyte.toHex

class RootOfTrust(
    private val seq: ASN1Sequence
) {
    class SequenceIndex {
        companion object {
            val VerifiedBootKey = 0
            val DeviceLocked = 1
            val VerifiedBootState = 2
            val VerifiedBootHashIndex = 3
        }
    }

    private fun getInteger(index: Int): Int? =
        (seq.getObjectAt(index) as ASN1Integer).getInt()

    private fun getEnumerated(index: Int): Int? =
        seq.getObjectAt(index).getInt()

    private fun getBoolean(index: Int): Boolean? {
        val raw = seq.getObjectAt(index)

        if (raw is DERNull)
            return null

        return (raw as ASN1Boolean).getBoolean()
    }

    fun getHex(index: Int): String? =
        seq.getObjectAt(index).getBytes().toHex()

    val verifiedBootKey: String?
        get() = getHex(SequenceIndex.VerifiedBootKey)

    val deviceLocked: Boolean?
        get() = getBoolean(SequenceIndex.DeviceLocked)

    val verifiedBootState: VerifiedBootState?
        get() {
            val int = getEnumerated(SequenceIndex.VerifiedBootState) ?: return null
            return VerifiedBootState.fromValue(int)
        }

    fun summary(): List<Pair<String, String?>> = listOf(
        Pair("Root of Trust", ""),
        Pair("Device Locked", deviceLocked?.toString()),
        Pair("Verified Boot Key", verifiedBootKey),
        Pair("Verified Boot State", verifiedBootState?.toString() ?: null)
    )
}