package za.co.indrajala.fluid.model.rqrsp

data class KeyAttestationInitRsp(
        val attestationID: String,
        val challenge: String,
        val keyLifeTimeMinutes: Int,
        val keySizeBits: Int,
        val keySerialNumber: Long
    ) {

}