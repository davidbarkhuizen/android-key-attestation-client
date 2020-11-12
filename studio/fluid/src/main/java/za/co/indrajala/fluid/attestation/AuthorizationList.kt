package za.co.indrajala.fluid.attestation

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.attestation.enums.*
import za.co.indrajala.fluid.crypto.bouncy_castle.*
import java.util.*

class AuthorizationList(
    private val seq: ASN1Sequence
) {
    class TagNumber {
        companion object {
            val Purpose = 1
            val Algorithm = 2
            val KeySize = 3
            val Digest = 5
            val Padding = 6
            val ECCurve = 10
            val RsaPublicExponent = 200
            val RollbackResistance = 303
            val ActiveDateTime = 400
            val OriginationDateTime = 401
            val UsageExpireDateTime = 402
            val NoAuthRequired = 503
            val UserAuthType = 504
            val AuthTimeout = 505
            val AllowWhileOnBody = 506

            val KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507
            val KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 508
            val KM_TAG_UNLOCKED_DEVICE_REQUIRED = 509
            val KM_TAG_ALL_APPLICATIONS = 600
            val KM_TAG_APPLICATION_ID = 601

            val CreationDateTime = 701
            val Origin = 702

            val RollbackResistant = 703

            val RootOfTrust = 704
            val OSVersion = 705
            val OSPatchLevel = 706
            val AttestationApplicationID = 709

            val KM_TAG_ATTESTATION_ID_BRAND = 710
            val KM_TAG_ATTESTATION_ID_DEVICE = 711
            val KM_TAG_ATTESTATION_ID_PRODUCT = 712
            val KM_TAG_ATTESTATION_ID_SERIAL = 713
            val KM_TAG_ATTESTATION_ID_IMEI = 714
            val KM_TAG_ATTESTATION_ID_MEID = 715
            val KM_TAG_ATTESTATION_ID_MANUFACTURER = 716
            val KM_TAG_ATTESTATION_ID_MODEL = 717
            val KM_TAG_VENDOR_PATCH_LEVEL = 718
            val KM_TAG_BOOT_PATCH_LEVEL = 719
            val KM_TAG_DEVICE_UNIQUE_ATTESTATION = 720
            // --------------------------

            val ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0
            val ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1
            val ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0
            val ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1
        }
    }

    val purpose: Set<Purpose>?
        get() = seq.getIntSetForTag(TagNumber.Purpose)?.map { Purpose.fromValue(it) }?.toSet()

    val algorithm: Algorithm?
        get() {
            val algoInt = seq.getIntForTag(TagNumber.Algorithm) ?: return null
            return Algorithm.fromValue(algoInt)
        }

    val keySize: Int?
        get() = seq.getIntForTag(TagNumber.KeySize)

    val digest: Set<Digest>?
        get() = seq.getIntSetForTag(TagNumber.Digest)?.map { Digest.fromValue(it) }?.toSet()

    val padding: Set<Padding>?
        get() = seq.getIntSetForTag(TagNumber.Padding)?.map { Padding.fromValue(it) }?.toSet()

    val ecCurve: Set<Padding>?
        get() = seq.getIntSetForTag(TagNumber.ECCurve)?.map { Padding.fromValue(it) }?.toSet()

    val rsaPublicExponent: Int?
        get() = seq.getIntForTag(TagNumber.RsaPublicExponent)

    val activeDateTime: Date?
        get() = seq.getULongDateForTag(TagNumber.ActiveDateTime)

    val originationExpireDateTime: Date?
        get() = seq.getULongDateForTag(TagNumber.OriginationDateTime)

    val usageExpireDateTime: Date?
        get() = seq.getULongDateForTag(TagNumber.UsageExpireDateTime)

    val noAuthRequired: Boolean?
        get() = seq.getBooleanForTag(TagNumber.NoAuthRequired)

    val creationDateTime: Date?
        get() = seq.getULongDateForTag(TagNumber.CreationDateTime)

    val origin: Origin?
        get() {
            val originVal = seq.getIntForTag(TagNumber.Origin) ?: return null
            return Origin.fromValue(originVal)
        }

    val osVersion: Int?
        get() = seq.getIntForTag(TagNumber.OSVersion)

    val osPatchLevel: Int?
        get() = seq.getIntForTag(TagNumber.OSPatchLevel)

    val rootOfTrust: RootOfTrust?
        get() {
            val value = seq.getForTag(TagNumber.RootOfTrust)
                ?: return null
            return RootOfTrust(value as ASN1Sequence)
        }

    val applicationId: AttestationApplicationId?
        get() {
            val value = (
                seq.getForTag(TagNumber.AttestationApplicationID)
                    ?: return null
            ) as DEROctetString

            return AttestationApplicationId(value)
        }

    val userAuthType: HardwareAuthenticatorType?
        get() {
            val value = seq.getUIntForTag(TagNumber.UserAuthType) ?: return null
            return HardwareAuthenticatorType.fromValue(value)
        }

    val authTimeout: Int?
        get() = seq.getIntForTag(TagNumber.AuthTimeout)

    val rollbackResistance: Boolean?
        get() = seq.getBooleanForTag(TagNumber.RollbackResistance)

    val rollbackResistant: Boolean?
        get() = seq.getBooleanForTag(TagNumber.RollbackResistant)

    /*

    allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
    allApplications  [600] EXPLICIT NULL OPTIONAL,

    attestationIdBrand  [710] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdDevice  [711] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdProduct  [712] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdSerial  [713] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdImei  [714] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdMeid  [715] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
    attestationIdModel  [717] EXPLICIT OCTET_STRING OPTIONAL,
     */

    fun summary(): List<Pair<String, String?>> = listOf(
        Pair("Purpose", purpose?.toString()),
        Pair("Algorithm", algorithm?.toString()),
        Pair("Key Size", keySize?.toString()),
        Pair("Digest", digest?.toString()),
        Pair("Padding", padding?.toString()),
        Pair("EC Curve", ecCurve?.toString()),
        Pair("RSA Public Exponent", rsaPublicExponent?.toString()),
        Pair("Active Date Time", activeDateTime?.toString()),
        Pair("No Auth Reqd", noAuthRequired?.toString()),
        Pair("Creation Date Time", creationDateTime?.toString()),
        Pair("Usage Expire Date Time", usageExpireDateTime?.toString()),
        Pair("Origination Expire Date Time", originationExpireDateTime?.toString()),
        Pair("Origin", origin?.toString()),
        Pair("OS Version", osVersion?.toString()),
        Pair("OS Patch Level", osPatchLevel?.toString()),
        Pair("User Auth Type", userAuthType?.toString()),
        Pair("Auth Timeout", authTimeout?.toString()),
        Pair("Rollback Resistant", rollbackResistant?.toString()),
        Pair("Rollback Resistance", rollbackResistance?.toString()),
        *(rootOfTrust?.summary() ?: List<Pair<String, String?>>(0){ Pair("","") }).toTypedArray(),
        *(applicationId?.summary() ?: List<Pair<String, String?>>(0){ Pair("","") }).toTypedArray()
    )
}