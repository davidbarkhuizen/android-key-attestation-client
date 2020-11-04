package za.co.indrajala.fluid.model.device

data class DevRegInitRsp(
    val keyAttestationChallenge: String,
    val registrationID: String,
    val keyLifeTimeMinutes: Int,
    val keySizeBits: Int,
    val keySN: Long
)