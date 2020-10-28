package za.co.indrajala.fluid.asn1

enum class Asn1Class (val value: UByte) {

    Universal(0.toUByte()),
    Application(1.toUByte()),
    ContextSpecific(2.toUByte()),
    Private(3.toUByte());

    companion object {
        private val map = Asn1Class.values().associateBy(Asn1Class::value)
        fun fromValue(value: UByte): Asn1Class? {
            println(value)
            return map[value]
        }
    }
}