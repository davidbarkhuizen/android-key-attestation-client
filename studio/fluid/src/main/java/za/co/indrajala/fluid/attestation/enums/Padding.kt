package za.co.indrajala.fluid.attestation.enums

enum class Padding(val value: Int) {

    NONE(1),
    RSA_OAEP(2),
    RSA_PSS(3),
    RSA_PKCS1_1_5_ENCRYPT(4),
    RSA_PKCS1_1_5_SIGN(5),
    PKCS7(64);

    companion object {
        private val map = Padding.values().associateBy(Padding::value)
        fun fromValue(value: Int): Padding {
            return map[value] ?: error("$value")
        }
    }
}