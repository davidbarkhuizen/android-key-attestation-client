package za.co.indrajala.fluid.asn1

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class X509 {
    companion object {

        private val certFactory = CertificateFactory.getInstance("X.509");

        fun fromPEM(pem: String) =
            certFactory.generateCertificate(
                (ByteArrayInputStream(pem.toByteArray()))
            ) as X509Certificate
    }
}