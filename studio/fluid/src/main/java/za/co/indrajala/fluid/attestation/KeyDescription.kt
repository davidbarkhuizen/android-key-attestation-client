package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import za.co.indrajala.fluid.asn1.*
import za.co.indrajala.fluid.attestation.enums.SecurityLevel
import za.co.indrajala.fluid.ubyte.toHex
import java.security.cert.X509Certificate

class KeyDescription(
    private val seq: ASN1Sequence
) {
    val attestationVersion: Int?
        get() = seq.getIntegerAtIndex(Index.AttestationVersion)

    val attestationSecurityLevel: SecurityLevel?
        get() = SecurityLevel.fromValue(seq.getEnumeratedAtIndex(Index.AttestationSecurityLevel))

    val keymasterVersion: Int?
        get() = seq.getIntegerAtIndex(Index.KeymasterVersion)

    val keymasterSecurityLevel: SecurityLevel?
        get() = SecurityLevel.fromValue(seq.getEnumeratedAtIndex(Index.KeyMasterSecurityLevel))

    val attestationChallenge: String?
        get() = seq.getHexAtIndex(Index.AttestationChallenge)

    val uniqueId: String?
        get() = seq.getHexAtIndex(Index.UniqueID)

    val softwareEnforced: AuthorizationList?
        get() {
            val z = seq.getSequenceAtIndex(Index.SW_Enforced)
                ?: return null

            return AuthorizationList(z)
        }

    val teeEnforced: AuthorizationList?
        get() {
            val z = seq.getSequenceAtIndex(Index.TEE_Enforced)
                ?: return null

            return AuthorizationList(z)
        }
    fun summary(): List<Pair<String, String?>> = listOf(
        Pair("Attestation Version", attestationVersion?.toString()),
        Pair("Attestation Security Level", attestationSecurityLevel?.toString()),
        Pair("KeyMaster Version", keymasterVersion?.toString()),
        Pair("KeyMaster Security Level", keymasterSecurityLevel?.toString()),
        Pair("Attestation Challenge", attestationChallenge),
        Pair("Unique ID", uniqueId),
        Pair("SOFTWARE ENFORCED", ""),
        *(softwareEnforced?.summary() ?: List<Pair<String, String?>>(0){ Pair("","") }).toTypedArray(),
        Pair("TEE ENFORCED", ""),
        *(teeEnforced?.summary() ?: List<Pair<String, String?>>(0){ Pair("","") }).toTypedArray()
    )

    companion object {

        private const val AttestationExtensionObjectID = "1.3.6.1.4.1.11129.2.1.17"

        class Index {
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

            val attExtBytes = cert.getExtensionValue(AttestationExtensionObjectID)
                ?: return null

            val bytes = ((ASN1InputStream(attExtBytes).readObject() ?: return null) as ASN1OctetString)
                .octets

            val asn1Seq = ASN1InputStream(bytes).readObject() as ASN1Sequence

            return KeyDescription(asn1Seq)
        }
    }
}