package za.co.indrajala.fluid.crypto

import android.util.Base64
import za.co.indrajala.fluid.util.toHexString
import java.security.cert.Certificate

// online parser @ https://www.sslshopper.com/certificate-decoder.html
//
fun Certificate.toPEM() : String = listOf(
    "-----BEGIN CERTIFICATE-----",
    Base64.encodeToString(encoded, Base64.DEFAULT).toString(),
    "-----END CERTIFICATE-----"
).joinToString("\n")

// online parser @ https://lapo.it/asn1js/
//
fun Certificate.toDER() =
    encoded.toHexString()