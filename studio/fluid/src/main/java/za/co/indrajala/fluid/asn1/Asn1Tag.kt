package za.co.indrajala.fluid.asn1

enum class Asn1Tag (val value: UByte) {

    end_of_content(0.toUByte()),
    boolean(1.toUByte()),
    integer(2.toUByte()),
    bit_string(3.toUByte()),
    octet_string(4.toUByte()),
    null_(5.toUByte()),
    object_identifier(6.toUByte()),
    object_descriptor(7.toUByte()),
    external_(8.toUByte()),
    real_float(9.toUByte()),
    enumerated(10.toUByte()),
    embedded_pdv(11.toUByte()),
    utf8_string(12.toUByte()),
    relative_oid(13.toUByte()),
    time(14.toUByte()),
    reserved(15.toUByte()),
    sequence(16.toUByte()),
    set(17.toUByte()),
    numeric_string(18.toUByte()),
    printable_string(19.toUByte()),
    t61_string(20.toUByte()),
    videotex_string(21.toUByte()),
    ia5_string(22.toUByte()),
    utc_time(23.toUByte()),
    generalized_time(24.toUByte()),
    graphic_string(25.toUByte()),
    visible_string(26.toUByte()),
    general_string(27.toUByte()),
    universal_string(28.toUByte()),
    character_string(29.toUByte()),
    bmp_string(30.toUByte()),
    date(31.toUByte()),
    time_of_day(32.toUByte()),
    date_time(33.toUByte()),
    duration(34.toUByte()),
    oid_iri(35.toUByte()),
    relative_oid_iri(36.toUByte());

    companion object {
        private val map = Asn1Tag.values().associateBy(Asn1Tag::value)
        fun fromValue(value: UByte): Asn1Tag {
            return map[value] ?: error("$value")
        }
    }
}