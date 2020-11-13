package za.co.indrajala.fluid.model.rqrsp

class KeyAttestationRq(
        val attestationID: String,
        val hwAttestationKeyChain: List<String>,
)