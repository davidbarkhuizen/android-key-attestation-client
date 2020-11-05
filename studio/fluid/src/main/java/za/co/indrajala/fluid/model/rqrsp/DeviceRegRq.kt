package za.co.indrajala.fluid.model.rqrsp

class DeviceRegRq(
    val registrationID: String,
    val hwAttestationKeyChain: List<String>,
)