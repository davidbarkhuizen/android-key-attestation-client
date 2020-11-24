package za.co.indrajala.fluid.model

import za.co.indrajala.fluid.attestation.enums.Algorithm
import za.co.indrajala.fluid.attestation.enums.Digest
import za.co.indrajala.fluid.attestation.enums.Padding
import za.co.indrajala.fluid.attestation.enums.Purpose

class AsymmetricKeyParameters (
        val requireHSM: Boolean,
        val challenge: String,
        val purpose: Purpose,
        val sizeInBits: Int,
        val serialNumber: ULong,
        val lifetimeMinutes: Int,
        val digest: Digest,
        val padding: Padding,
        val algorithm: Algorithm,
        val rsaExponent: ULong,
        val ecCurve: String?
)