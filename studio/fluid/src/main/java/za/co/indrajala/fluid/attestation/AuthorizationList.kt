package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.asn1.getInt

class AuthorizationList(
    seq: Array<ASN1Encodable>
) {
    private val _lookup: Map<Int, ASN1Primitive> = mapOf(
        *seq.map {
            val asTaggedOb = it as ASN1TaggedObject
            Pair<Int, ASN1Primitive>(it.tagNo, it.getObject())
        }.toTypedArray()
    )

    private fun getIntegerSet(index: Int): Set<Int>? =
        (_lookup[index] as ASN1Set?)?.map { it.getInt() }?.toSet()

    private fun getInteger(index: Int): Int? =
        (_lookup[index] as ASN1Integer).getInt()


    val purpose: Set<Int>?
        get() = getIntegerSet(AttConst.KM_TAG_PURPOSE)

    val algorithm: Int?
        get() = getInteger(AttConst.KM_TAG_ALGORITHM)

    val keySize: Int?
        get() = getInteger(AttConst.KM_TAG_KEY_SIZE)

    val digest: Set<Int>?
        get() = getIntegerSet(AttConst.KM_TAG_DIGEST)

    fun summary() = listOf(
        "Purpose $purpose",
        "Algorithm $algorithm",
        "Key Size $keySize",
        "Digest $digest",
    )
}