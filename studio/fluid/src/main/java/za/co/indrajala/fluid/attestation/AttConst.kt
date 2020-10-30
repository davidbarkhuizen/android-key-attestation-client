package za.co.indrajala.fluid.attestation

class AttConst {
    companion object {

        // Authorization list tags. The list is in this AOSP file:
        // hardware/libhardware/include/hardware/keymaster_defs.h
        val KM_TAG_PURPOSE = 1
        val KM_TAG_ALGORITHM = 2
        val KM_TAG_KEY_SIZE = 3
        val KM_TAG_DIGEST = 5
        val KM_TAG_PADDING = 6
        val KM_TAG_EC_CURVE = 10
        val KM_TAG_RSA_PUBLIC_EXPONENT = 200
        val KM_TAG_ROLLBACK_RESISTANCE = 303
        val KM_TAG_ACTIVE_DATE_TIME = 400
        val KM_TAG_ORIGINATION_EXPIRE_DATE_TIME = 401
        val KM_TAG_USAGE_EXPIRE_DATE_TIME = 402
        val KM_TAG_NO_AUTH_REQUIRED = 503
        val KM_TAG_USER_AUTH_TYPE = 504
        val KM_TAG_AUTH_TIMEOUT = 505
        val KM_TAG_ALLOW_WHILE_ON_BODY = 506
        val KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507
        val KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 508
        val KM_TAG_UNLOCKED_DEVICE_REQUIRED = 509
        val KM_TAG_ALL_APPLICATIONS = 600
        val KM_TAG_APPLICATION_ID = 601
        val KM_TAG_CREATION_DATE_TIME = 701
        val KM_TAG_ORIGIN = 702
        val KM_TAG_ROLLBACK_RESISTANT = 703
        val KM_TAG_ROOT_OF_TRUST = 704
        val KM_TAG_OS_VERSION = 705
        val KM_TAG_OS_PATCH_LEVEL = 706
        val KM_TAG_ATTESTATION_APPLICATION_ID = 709
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
        val ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX = 0
        val ROOT_OF_TRUST_DEVICE_LOCKED_INDEX = 1
        val ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX = 2
        val ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3
        val ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0
        val ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1
        val ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0
        val ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1

        // Some security values. The complete list is in this AOSP file:
        // hardware/libhardware/include/hardware/keymaster_defs.h
        val KM_SECURITY_LEVEL_SOFTWARE = 0
        val KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        val KM_SECURITY_LEVEL_STRONG_BOX = 2
        val KM_VERIFIED_BOOT_STATE_VERIFIED = 0
        val KM_VERIFIED_BOOT_STATE_SELF_SIGNED = 1
        val KM_VERIFIED_BOOT_STATE_UNVERIFIED = 2
        val KM_VERIFIED_BOOT_STATE_FAILED = 3

        // Unsigned max value of 32-bit integer, 2^32 - 1
        val UINT32_MAX = (Int.MAX_VALUE.toLong() shl 1) + 1
    }
}