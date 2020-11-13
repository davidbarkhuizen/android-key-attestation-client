package za.co.indrajala.fluid.model.rqrsp

import za.co.indrajala.fluid.model.AsymmetricKeyParameters

data class KeyAttestationInitRsp(
    val succeeded: Boolean,
    val reference: String,
    val keyParams: AsymmetricKeyParameters
)