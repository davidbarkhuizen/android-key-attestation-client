package za.co.indrajala.fluid.key_attestation.enums

enum class Purpose(val value: Int) {
    Encrypt(0),
    Decrypt(1),
    Sign(2),
    Verify(3),
    DeriveKey(4),
    WrapKey(5);

    companion object {
        private val map = Purpose.values().associateBy(Purpose::value)
        fun fromValue(value: Int): Purpose {
            return map[value] ?: error("$value")
        }
    }
}