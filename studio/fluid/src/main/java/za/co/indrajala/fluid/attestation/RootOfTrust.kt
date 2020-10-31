package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.asn1.*
import za.co.indrajala.fluid.attestation.enums.VerifiedBootState
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

    val verifiedBootKey: String?
        get() = seq.getHexAtIndex(SequenceIndex.VerifiedBootKey)

    val deviceLocked: Boolean?
        get() = seq.getBooleanAtIndex(SequenceIndex.DeviceLocked)

    val verifiedBootState: VerifiedBootState?
        get() {
            val int = seq.getEnumeratedAtIndex(SequenceIndex.VerifiedBootState) ?: return null
            return VerifiedBootState.fromValue(int)
        }

    fun summary(): List<Pair<String, String?>> = listOf(
        Pair("Root of Trust", ""),
        Pair("Device Locked", deviceLocked?.toString()),
        Pair("Verified Boot Key", verifiedBootKey),
        Pair("Verified Boot State", verifiedBootState?.toString() ?: null)
    )
}