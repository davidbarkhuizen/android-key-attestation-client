package za.co.indrajala.fluid.attestation.authlist

enum class Digest(val value: Int) {
    NONE(0),
    MD5(1),
    SHA1(2),
    SHA_2_224(3),
    SHA_2_256(4),
    SHA_2_384(5),
    SHA_2_512(6);

    companion object {
        private val map = Digest.values().associateBy(Digest::value)
        fun fromValue(value: Int): Digest {
            return map[value] ?: error("$value")
        }
    }
}