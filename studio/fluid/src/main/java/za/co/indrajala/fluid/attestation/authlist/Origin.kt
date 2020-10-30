package za.co.indrajala.fluid.attestation.authlist

enum class Origin(val value: Int) {

    GENERATED(0),
    DERIVED(1),
    IMPORTED(2),
    UNKNOWN(3);

    companion object {
        private val map = Origin.values().associateBy(Origin::value)
        fun fromValue(value: Int): Origin {
            return map[value] ?: error("$value")
        }
    }
}