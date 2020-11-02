package za.co.indrajala.fluid.crypto.bouncy_castle

import org.bouncycastle.asn1.*
import za.co.indrajala.fluid.bit.toHex
import java.math.BigInteger

fun ASN1Sequence.getSequenceAtIndex(index: Int): ASN1Sequence? {
    return (this.getObjectAt(index) ?: return null) as ASN1Sequence
}

fun ASN1Sequence.getIntegerAtIndex(index: Int): Int? =
    (this.getObjectAt(index) as ASN1Integer).getInt()

fun ASN1Sequence.getEnumeratedAtIndex(index: Int): Int? =
    (this.getObjectAt(index) as ASN1Enumerated).getInt()

fun ASN1Sequence.getBooleanAtIndex(index: Int): Boolean? {
    val raw = this.getObjectAt(index)

    if (raw is DERNull)
        return null

    return (raw as ASN1Boolean).getBoolean()
}

fun ASN1Sequence.getHexAtIndex(index: Int): String? =
    this.getObjectAt(index).getBytes().toHex()

fun ASN1Sequence.getForTag(tagNumber: Int): ASN1Primitive? {

    val o = this.firstOrNull {
        if (it is ASN1TaggedObject)
            it.tagNo == tagNumber
        else
            false
    } ?: return null

    return (o as ASN1TaggedObject).`object`
}

fun ASN1Sequence.getIntSetForTag(tagNumber: Int): Set<Int>? {
    return ((this.getForTag(tagNumber) ?: return null) as ASN1Set)
        .map { it.getInt() }
        .toSet()
}

fun ASN1Sequence.getIntForTag(tagNumber: Int): Int? {
    return ((this.getForTag(tagNumber) ?: return null) as ASN1Integer).getInt()
}

fun ASN1Sequence.getUIntForTag(tagNumber: Int): UInt? {
    return ((this.getForTag(tagNumber) ?: return null) as ASN1Integer).getInt().toUInt()
}

fun ASN1Sequence.getBigIntegerForTag(tagNumber: Int): BigInteger? {
    return (this.getForTag(tagNumber) ?: return null).getBigInt()
}

fun ASN1Sequence.getHexForTag(tagNumber: Int): String? =
    this.getForTag(tagNumber)?.getBytes()?.toHex()

fun ASN1Sequence.getBooleanForTag(tagNumber: Int): Boolean? {

    val raw =  this.getForTag(tagNumber)
        ?: return null

    if (raw is DERNull)
        return null

    return (raw as ASN1Boolean).getBoolean()
}


