package za.co.indrajala.fluid.attestation.enums

enum class VerifiedBootState(val value: Int) {

    Verified  (0),
    SelfSigned  (1),
    Unverified  (2),
    Failed  (3);

    companion object {
        private val map = values().associateBy(VerifiedBootState::value)
        fun fromValue(value: Int): VerifiedBootState? = map[value]
    }
}