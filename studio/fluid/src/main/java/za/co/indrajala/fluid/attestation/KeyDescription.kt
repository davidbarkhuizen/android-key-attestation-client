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
    val uniqueId: String,
//    val softwareEnforced: AuthorizationList,
    val teeEnforced: AuthorizationList,
) {
    fun summary(): List<String> = listOf(
        "Attestation Version: $attestationVersion",
        "Attestation Security Level: $attestationSecurityLevel",
        "KeyMaster Version: $keymasterVersion",
        "KeyMaster Security Level: $keymasterSecurityLevel",
        "Attestation Challenge: $attestationChallenge",
        "Unique ID: $uniqueId",
//        "SOFTWARE ENFORCED",
//        *softwareEnforced.summary().toTypedArray(),
        "TEE ENFORCED",
        *teeEnforced.summary().toTypedArray(),
    )

    companion object {

        private const val ATT_EXT_OID = "1.3.6.1.4.1.11129.2.1.17"

        class Indices {
            companion object {
                val ATTESTATION_VERSION = 0
                val ATTESTATION_SECURITY_LEVEL = 1
                val KEYMASTER_VERSION = 2
                val KEYMASTER_SECURITY_LEVEL = 3
                val ATTESTATION_CHALLENGE = 4
                val UNIQUE_ID = 5
                val SW_ENFORCED = 6
                val TEE_ENFORCED = 7
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
                attestationVersion = getInt(Indices.ATTESTATION_VERSION),
                attestationSecurityLevel = SecurityLevel.fromValue(getInt(Indices.ATTESTATION_SECURITY_LEVEL)),
                keymasterVersion = getInt(Indices.KEYMASTER_VERSION),
                keymasterSecurityLevel = SecurityLevel.fromValue(getInt(Indices.KEYMASTER_SECURITY_LEVEL)),
                attestationChallenge = getHex(Indices.ATTESTATION_CHALLENGE),
                uniqueId = getHex(Indices.UNIQUE_ID),
//                softwareEnforced = AuthorizationList(getSequence(Indices.SW_ENFORCED).toArray()),
                teeEnforced = AuthorizationList(getSequence(Indices.TEE_ENFORCED).toArray()),
            )
        }
    }
}