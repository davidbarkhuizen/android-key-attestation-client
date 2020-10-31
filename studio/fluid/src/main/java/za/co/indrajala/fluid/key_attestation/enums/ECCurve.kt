package za.co.indrajala.fluid.key_attestation.enums

enum class ECCurve(val value: Int) {

    P_224(0),
    P_256(1),
    P_384(2),
    P_521(3);

    companion object {
        private val map = ECCurve.values().associateBy(ECCurve::value)
        fun fromValue(value: Int): ECCurve {
            return map[value] ?: error("$value")
        }
    }
}