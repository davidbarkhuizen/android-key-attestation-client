package za.co.indrajala.fluid.attestation.authlist

enum class Algorithm(val value: Int) {
    RSA(1),
    EC(3),
    AES(32),
    HMAC(128);

    companion object {
        private val map = Algorithm.values().associateBy(Algorithm::value)
        fun fromValue(value: Int): Algorithm {
            return map[value] ?: error("$value")
        }
    }
}