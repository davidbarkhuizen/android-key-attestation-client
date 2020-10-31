package za.co.indrajala.fluid.asn1_poc

enum class Asn1Tag (val value: ULong) {

    end_of_content(0.toULong()),
    boolean(1.toULong()),
    integer(2.toULong()),
    bit_string(3.toULong()),
    octet_string(4.toULong()),
    null_(5.toULong()),
    object_identifier(6.toULong()),
    object_descriptor(7.toULong()),
    external_(8.toULong()),
    real_float(9.toULong()),
    enumerated(10.toULong()),
    embedded_pdv(11.toULong()),
    utf8_string(12.toULong()),
    relative_oid(13.toULong()),
    time(14.toULong()),
    reserved(15.toULong()),
    sequence(16.toULong()),
    set(17.toULong()),
    numeric_string(18.toULong()),
    printable_string(19.toULong()),
    t61_string(20.toULong()),
    videotex_string(21.toULong()),
    ia5_string(22.toULong()),
    utc_time(23.toULong()),
    generalized_time(24.toULong()),
    graphic_string(25.toULong()),
    visible_string(26.toULong()),
    general_string(27.toULong()),
    universal_string(28.toULong()),
    character_string(29.toULong()),
    bmp_string(30.toULong()),
    date(31.toULong()),
    time_of_day(32.toULong()),
    date_time(33.toULong()),
    duration(34.toULong()),
    oid_iri(35.toULong()),
    relative_oid_iri(36.toULong());

    companion object {
        private val map = Asn1Tag.values().associateBy(Asn1Tag::value)
        fun fromValue(value: ULong): Asn1Tag {
            return map[value] ?: error("$value")
        }
    }
}