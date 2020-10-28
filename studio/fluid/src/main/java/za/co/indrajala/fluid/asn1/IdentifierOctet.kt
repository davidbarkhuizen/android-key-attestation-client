package za.co.indrajala.fluid.asn1

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

    init {
        val id = b.shl(1)
    }
}