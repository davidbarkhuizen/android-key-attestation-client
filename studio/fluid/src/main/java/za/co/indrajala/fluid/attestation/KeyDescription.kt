package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.jcajce.provider.asymmetric.X509
import za.co.indrajala.fluid.FluidKeyStore
import za.co.indrajala.fluid.asn1.getBytes
import za.co.indrajala.fluid.asn1.getInt
import za.co.indrajala.fluid.ubyte.toHex
import za.co.indrajala.fluid.util.log
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class KeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: String,
    val uniqueId: String
//    val softwareEnforced: AuthorizationList,
//    val teeEnforced: AuthorizationList,
) {
    fun summary(): List<String> = listOf(
        "Attestation Version: $attestationVersion",
        "Attestation Security Level: $attestationSecurityLevel",
        "KeyMaster Version: $keymasterVersion",
        "KeyMaster Security Level: $keymasterSecurityLevel",
        "Attestation Challenge: $attestationChallenge",
        "Unique ID: $uniqueId"
    )

    companion object {

        private const val ATT_EXT_OID = "1.3.6.1.4.1.11129.2.1.17"

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

            return KeyDescription(
                attestationVersion = getInt(AttConst.ATTESTATION_VERSION_INDEX),
                attestationSecurityLevel = SecurityLevel.fromValue(getInt(AttConst.ATTESTATION_SECURITY_LEVEL_INDEX)),
                keymasterVersion = getInt(AttConst.KEYMASTER_VERSION_INDEX),
                keymasterSecurityLevel = SecurityLevel.fromValue(getInt(AttConst.KEYMASTER_SECURITY_LEVEL_INDEX)),
                attestationChallenge = getHex(AttConst.ATTESTATION_CHALLENGE_INDEX),
                uniqueId = getHex(AttConst.UNIQUE_ID_INDEX)
            )
        }
    }
}