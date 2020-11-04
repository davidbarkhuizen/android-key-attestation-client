package za.co.indrajala.fluid.model.device

class DevRegCompletionRq(
    val registrationID: String,
    val hwAttestationKeyChain: List<String>,
)