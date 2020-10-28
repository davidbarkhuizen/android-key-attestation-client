package za.co.indrajala.fluid.asn1

import za.co.indrajala.fluid.ubyte.UByteMask
import za.co.indrajala.fluid.ubyte.shl

class IdentifierOctet(val b: UByte, val isLeading: Boolean) {

    // Leading Octet
    //
    // 8,7      tag class
    // 6        primitive | constructed
    // 5...1    tag number (0...31)

    // Subsequent Octets
    //
    // 8        continues in next octet
    // 7...1    tag number (0...127)

    val asn1Class: Asn1Class

    init {

        println("b $b ${b.toString(radix = 2)}")
        val v = (b and UByteMask(8,7))
        println("v $v ${v.toString(radix = 2)}")

        val z = v.shl(2)
        println("z $z ${z.toString(radix = 2)}")

        asn1Class = Asn1Class.fromValue(z)!!
    }
}