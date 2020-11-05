package za.co.indrajala.fluid.model.rqrsp

data class DeviceRegPermissionRsp(
    val keyAttestationChallenge: String,
    val registrationID: String,
    val keyLifeTimeMinutes: Int,
    val keySizeBits: Int,
    val keySN: Long
)