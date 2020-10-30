package za.co.indrajala.fluid.attestation.authlist

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.asn1.getBoolean
import za.co.indrajala.fluid.asn1.getInt
import za.co.indrajala.fluid.attestation.AttConst

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
        (_lookup[index] as ASN1Integer?)?.getInt()

    private fun getBoolean(index: Int): Boolean? {
        val raw =  _lookup[index] ?: return null

        if (raw is DERNull)
            return null

        return (raw as ASN1Boolean).getBoolean()
    }

    val purpose: Set<Purpose>?
        get() = getIntegerSet(AttConst.KM_TAG_PURPOSE)?.map { Purpose.fromValue(it) }?.toSet()

    val algorithm: Algorithm?
        get() {
            val algoInt = getInteger(AttConst.KM_TAG_ALGORITHM) ?: return null
            return Algorithm.fromValue(algoInt)
        }

    val keySize: Int?
        get() = getInteger(AttConst.KM_TAG_KEY_SIZE)

    val digest: Set<Digest>?
        get() = getIntegerSet(AttConst.KM_TAG_DIGEST)?.map { Digest.fromValue(it) }?.toSet()

    val padding: Set<Padding>?
        get() = getIntegerSet(AttConst.KM_TAG_PADDING)?.map { Padding.fromValue(it) }?.toSet()

    val ecCurve: Set<Padding>?
        get() = getIntegerSet(AttConst.KM_TAG_EC_CURVE)?.map { Padding.fromValue(it) }?.toSet()

    val rsaPublicExponent: Int?
        get() = getInteger(AttConst.KM_TAG_RSA_PUBLIC_EXPONENT)

    val activeDateTime: Int?
        get() = getInteger(AttConst.KM_TAG_ACTIVE_DATE_TIME)

    val originationExpireDateTime: Int?
        get() = getInteger(AttConst.KM_TAG_ORIGINATION_EXPIRE_DATE_TIME)

    val usageExpireDateTime: Int?
        get() = getInteger(AttConst.KM_TAG_USAGE_EXPIRE_DATE_TIME)

    val noAuthRequired: Boolean?
        get() = getBoolean(AttConst.KM_TAG_NO_AUTH_REQUIRED)

    val creationDateTime: Int?
        get() = getInteger(AttConst.KM_TAG_CREATION_DATE_TIME)

    val origin: Origin?
        get() {
            val originVal = getInteger(AttConst.KM_TAG_ORIGIN) ?: return null
            return Origin.fromValue(originVal)
        }

    val osVersion: Int?
        get() = getInteger(AttConst.KM_TAG_OS_VERSION)

    val osPatchLevel: Int?
        get() = getInteger(AttConst.KM_TAG_OS_PATCH_LEVEL)

    val rootOfTrust: RootOfTrust?
        get() {
            val value = _lookup[AttConst.KM_TAG_ROOT_OF_TRUST] ?: return null
            return RootOfTrust(value as ASN1Sequence)
        }

    /*

    userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
    authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
    allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
    allApplications  [600] EXPLICIT NULL OPTIONAL,

    applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,

    rollbackResistant  [703] EXPLICIT NULL OPTIONAL,

    attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,

     */

    fun summary() = listOf(
        "Purpose $purpose",
        "Algorithm $algorithm",
        "Key Size $keySize",
        "Digest $digest",
        "Padding $padding",
        "EC Curve $ecCurve",
        "RSA Public Exponent $rsaPublicExponent",
        "Active Date Time $activeDateTime",
        "No Auth Reqd $noAuthRequired",
        "Creation Date Time $creationDateTime",
        "Usage Expire Date Time $usageExpireDateTime",
        "Origin $origin",
        "OS Version $osVersion",
        "OS Patch Level $osPatchLevel",
        "Root Of Trust: $rootOfTrust",
    )
}