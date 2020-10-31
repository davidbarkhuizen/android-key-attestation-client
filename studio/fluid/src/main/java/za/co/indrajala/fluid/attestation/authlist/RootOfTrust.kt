package za.co.indrajala.fluid.attestation.authlist

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.asn1.getBoolean
import za.co.indrajala.fluid.asn1.getBytes
import za.co.indrajala.fluid.asn1.getInt
import za.co.indrajala.fluid.ubyte.toHex

class RootOfTrust(
    private val seq: ASN1Sequence
) {
    class Indices {
        companion object {
            val VERIFIED_BOOT_KEY = 0
            val DEVICE_LOCKED = 1
            val VERIFIED_BOOT_STATE = 2
            val VERIFIED_BOOT_HASH_INDEX = 3
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
        get() = getHex(Indices.VERIFIED_BOOT_KEY)

    val deviceLocked: Boolean?
        get() = getBoolean(Indices.DEVICE_LOCKED)

    val verifiedBootState: VerifiedBootState?
        get() {
            val int = getEnumerated(Indices.VERIFIED_BOOT_STATE) ?: return null
            return VerifiedBootState.fromValue(int)
        }

    override fun toString(): String =
        "Device Locked $deviceLocked, Verified Boot State $verifiedBootState, Verified Boot Key $verifiedBootKey"
}