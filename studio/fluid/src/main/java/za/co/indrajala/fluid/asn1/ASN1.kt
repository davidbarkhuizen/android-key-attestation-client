package za.co.indrajala.fluid.asn1

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.util.ASN1Dump
import java.io.ByteArrayInputStream

class ASN1 {
    companion object {
        fun describe(asn1_der: ByteArray): String =
            ASN1Dump.dumpAsString(
                ASN1InputStream(ByteArrayInputStream(asn1_der)).readObject()
            )
    }
}