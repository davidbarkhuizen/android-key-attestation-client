package za.co.indrajala.fluid.asn1

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import java.math.BigInteger

fun ASN1Encodable.getBoolean() =
    when (this) {
        is ASN1Boolean -> this.isTrue
        else -> throw IllegalArgumentException("${this.javaClass.name} is not a boolean")
    }

fun ASN1Encodable.getBigInt(): BigInteger =
        when (this) {
            is ASN1Integer -> this.value
            is ASN1Enumerated -> this.value
            else ->
                throw IllegalArgumentException("${this.javaClass.name} is not an integer")
        }

fun ASN1Encodable.getInt(): Int =
    this.getBigInt().toInt()