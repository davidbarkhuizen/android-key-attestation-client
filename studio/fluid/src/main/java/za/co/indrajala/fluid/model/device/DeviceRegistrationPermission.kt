package za.co.indrajala.fluid.model.device

data class DeviceRegistrationPermission(
    val challenge: String,
    val registrationID: String,
    val keyLifeTimeMinutes: Int,
    val keySizeBits: Int,
    val keySN: Long
)