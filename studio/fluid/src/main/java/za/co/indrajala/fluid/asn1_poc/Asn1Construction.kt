package za.co.indrajala.fluid.asn1_poc

enum class Asn1Construction (val value: UByte) {

    Primitive(0.toUByte()),
    Constructed(1.toUByte());

    companion object {
        private val map = Asn1Construction.values().associateBy(Asn1Construction::value)
        fun fromValue(value: UByte): Asn1Construction {
            return map[value] ?: error("$value")
        }
    }
}