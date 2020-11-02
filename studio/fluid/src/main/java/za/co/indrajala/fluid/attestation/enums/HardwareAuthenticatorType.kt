package za.co.indrajala.fluid.attestation.enums

enum class HardwareAuthenticatorType(val value: UInt) {

    None(0u),
    Password(1u shl 0),
    Fingerprint(1u shl 1),
    Any(UInt.MAX_VALUE);

    companion object {
        private val map = values().associateBy(HardwareAuthenticatorType::value)
        fun fromValue(value: UInt?): HardwareAuthenticatorType? = map[value]
    }
}