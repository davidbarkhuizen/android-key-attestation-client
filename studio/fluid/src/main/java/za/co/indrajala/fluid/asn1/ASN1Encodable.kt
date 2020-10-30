package za.co.indrajala.fluid.asn1

import org.bouncycastle.asn1.*
import java.math.BigInteger

fun ASN1Encodable.getBoolean() =
    when (this) {
        is ASN1Boolean -> this.isTrue
        else -> throw IllegalArgumentException("${this.javaClass.name} is not an ASN1Boolean")
    }

fun ASN1Encodable.getBigInt(): BigInteger =
        when (this) {
            is ASN1Integer -> this.value
            is ASN1Enumerated -> this.value
            else ->
                throw IllegalArgumentException("${this.javaClass.name} is not an ASN1Integer")
        }

fun ASN1Encodable.getInt(): Int =
    this.getBigInt().toInt()


fun ASN1Encodable.getBytes(): ByteArray =
    when (this) {
        is ASN1OctetString -> this.octets
        else -> throw IllegalArgumentException("${this.javaClass.name} is not an ASN1OctetString")
    }