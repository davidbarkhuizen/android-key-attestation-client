package za.co.indrajala.fluid.crypto

import android.icu.util.GregorianCalendar
import android.security.keystore.KeyProperties
import java.math.BigInteger

data class AsymKeyParams(
    val keySizeBits: Int,
    val usages: KeyPurpose,
    val subjectCommonName: String,
    val certSN: BigInteger,
    val permittedDigest: String,
    val signaturePadding: String,
    val validFrom: GregorianCalendar,
    val validTo: GregorianCalendar
)