package za.co.indrajala.fluid.asn1

enum class Asn1Class (val value: UByte) {

    Universal(0.toUByte()),
    Application(1.toUByte()),
    ContextSpecific(2.toUByte()),
    Private(3.toUByte()),
}