package za.co.indrajala.fluid.asn1_poc

class Asn1Identifier(
    val klass: Asn1Class,
    val construction: Asn1Construction,
    val tag: Asn1Tag
) {
    // Leading Octet
    //
    // 8,7      tag class
    // 6        primitive | constructed
    // 5...1    tag number (0...31)

    // Subsequent Octets
    //
    // 8        continues in next octet
    // 7...1    tag number (0...127)
}