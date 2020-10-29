package za.co.indrajala.fluid.crypto

import android.icu.util.GregorianCalendar
import android.security.keystore.KeyProperties
import java.math.BigInteger

class AsymKeyParams(
    val subjectCommonName: String,
    certSN: Long,
    val keySizeBits: Int,
    val purpose: KeyPurpose,
    val digest: String,
    val signaturePadding: String? = null,
    val encryptionPadding: String? = null,
    val validFrom: GregorianCalendar,
    val validTo: GregorianCalendar
) {
    val certSN: BigInteger = BigInteger.valueOf(certSN)
}