package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.bit.toHex
import za.co.indrajala.fluid.crypto.bouncy_castle.getBytes

class AttestationApplicationId(
    octetString: ASN1OctetString
) {
    private val seq = ASN1InputStream(octetString.octets).readObject() as ASN1Sequence

    class SequenceIndex {
        companion object {
            val PackageInfos = 0
            val SignatureDigests = 1
        }
    }

    fun getHex(index: Int): String? =
        seq.getObjectAt(index).getBytes().toHex()

    val attPackageInfos: Set<AttestationPackageInfo>?
        get() = (seq.getObjectAt(SequenceIndex.PackageInfos) as ASN1Set?)?.map { AttestationPackageInfo(it.toASN1Primitive() as ASN1Sequence) }?.toSet()

    val signatureDigests: Set<String>?
        get() = (seq.getObjectAt(SequenceIndex.SignatureDigests) as ASN1Set?)?.map { it.getBytes().toHex() }?.toSet()

    fun summary(): List<Pair<String, String?>> {

        val ret: ArrayList<Pair<String, String?>> = arrayListOf()

        val sigDigests = signatureDigests
        if (sigDigests != null) {
            ret.addAll(sigDigests.map { Pair("Signature Digest", it) })
        }

        val packInfos = attPackageInfos
        packInfos?.forEach {
            ret.add(Pair("Attestation Package Info", ""))
            ret.addAll(it.summary())
        }

        return ret.toList()
    }
}