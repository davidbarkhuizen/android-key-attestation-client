package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import za.co.indrajala.fluid.asn1.getBytes
import za.co.indrajala.fluid.asn1.getInt
import za.co.indrajala.fluid.ubyte.toHex
import java.security.cert.X509Certificate

class KeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: String,
    val uniqueId: String?,
    val softwareEnforced: AuthorizationList,
    val teeEnforced: AuthorizationList,
) {
    fun summary(): List<Pair<String, String?>> = listOf(

        Pair("Attestation Version", attestationVersion?.toString()),
        Pair("Attestation Security Level", attestationSecurityLevel?.toString()),
        Pair("KeyMaster Version", keymasterVersion?.toString()),
        Pair("KeyMaster Security Level", keymasterSecurityLevel?.toString()),
        Pair("Attestation Challenge", attestationChallenge),
        Pair("Unique ID", uniqueId),
        Pair("SOFTWARE ENFORCED", ""),
        *softwareEnforced.summary().toTypedArray(),
        Pair("TEE ENFORCED", ""),
        *teeEnforced.summary().toTypedArray(),
    )

    companion object {

        private const val ATT_EXT_OID = "1.3.6.1.4.1.11129.2.1.17"

        class SequenceIndex {
            companion object {
                val AttestationVersion = 0
                val AttestationSecurityLevel = 1
                val KeymasterVersion = 2
                val KeyMasterSecurityLevel = 3
                val AttestationChallenge = 4
                val UniqueID = 5
                val SW_Enforced = 6
                val TEE_Enforced = 7
            }
        }

        fun fromX509Cert(cert: X509Certificate): KeyDescription? {

            val attExtBytes = cert.getExtensionValue(ATT_EXT_OID)
            if ((attExtBytes == null) || (attExtBytes.isEmpty())) {
                return null
            }

            val derSeqBytes = (ASN1InputStream(attExtBytes).readObject() as ASN1OctetString).octets
            val decodedSeq = ASN1InputStream(derSeqBytes).readObject() as ASN1Sequence

            fun getInt(index: Int): Int =
                decodedSeq.getObjectAt(index).getInt()

            fun getHex(index: Int): String =
                decodedSeq.getObjectAt(index).getBytes().toHex()

            fun getSequence(index: Int): ASN1Sequence =
                decodedSeq.getObjectAt(index) as ASN1Sequence

            return KeyDescription(
                attestationVersion = getInt(SequenceIndex.AttestationVersion),
                attestationSecurityLevel = SecurityLevel.fromValue(getInt(SequenceIndex.AttestationSecurityLevel)),
                keymasterVersion = getInt(SequenceIndex.KeymasterVersion),
                keymasterSecurityLevel = SecurityLevel.fromValue(getInt(SequenceIndex.KeyMasterSecurityLevel)),
                attestationChallenge = getHex(SequenceIndex.AttestationChallenge),
                uniqueId = getHex(SequenceIndex.UniqueID),
                softwareEnforced = AuthorizationList(getSequence(SequenceIndex.SW_Enforced).toArray()),
                teeEnforced = AuthorizationList(getSequence(SequenceIndex.TEE_Enforced).toArray()),
            )
        }
    }
}