package za.co.indrajala.fluid.crypto

data class DeviceFingerprint (
    val apiLevel: Int
) {
    override fun toString() =
        "API Level $apiLevel"
}