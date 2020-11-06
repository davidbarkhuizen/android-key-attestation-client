package za.co.indrajala.fluid.asn1_poc

import za.co.indrajala.fluid.bit.hexToUBytes
import za.co.indrajala.fluid.log

class DER {
    companion object {

        private const val logging = false

        fun parseOID(bytes: UByteArray) {

            val firstByte = bytes[0]
            if (logging) log.v(firstByte.toString(16))

            val firstNodeValue = firstByte / 40.toUByte()
            val secondNodeValue = firstByte - (firstNodeValue * 40.toUInt())

            val nodes = arrayListOf<ULong>(firstNodeValue.toULong(), secondNodeValue.toULong())

            var remainder = bytes.map { it }.takeLast(bytes.size - 1)

            while (remainder.isNotEmpty()) {

                val isLongForm = remainder[0].bitsAreSet(8)

                if (!isLongForm) {
                    nodes.add(remainder[0].toULong())
                    remainder = remainder.takeLast(remainder.size - 1)
                } else {

                    val head = remainder.takeWhile { it.bitsAreSet(8) }.toTypedArray()

                    val unpacked = listOf(
                        *head,
                        remainder[head.size]
                    ).map { it.toString(radix = 2).padStart(8, '0').takeLast(7) }
                        //.asReversed()
                        .joinToString("")

                    remainder = remainder.takeLast(remainder.size - (head.size + 1))

                    val packed =
                        if (unpacked.length % 8 == 0)
                            unpacked
                        else
                            "0".repeat(8 - (unpacked.length % 8)) + unpacked

                    val oid = packed.toULong(radix = 2)
                    nodes.add(oid)
                }
            }

            if (logging) log.v("OID: ${nodes.joinToString(".")}")
        }

        fun parse(hex: String) {

            if (logging) log.v("raw: $hex")

            val raw = hex.hexToUBytes()

            val b = raw[0]

            if (logging) log.v("b1 $b ${b.toString(radix = 2)}")

            val idClass = Asn1Class.fromValue(b.getStandAloneBitsValue(8,7))
            if (logging) log.v("class $idClass")

            val construction = Asn1Construction.fromValue(b.getStandAloneBitsValue(6))
            if (logging) log.v("construction $construction")

            // TODO validate that construction is permitted for universal tags

            val initialOctetTagNumber = b.getStandAloneBitsValue(1,2,3,4,5).toULong()

            val initialOctetTag = Asn1Tag.fromValue(initialOctetTagNumber)
                    ?: throw IllegalArgumentException(
                            "unexpected initial identifier tag value: $initialOctetTagNumber (source = ${b.toString(16)}")

            if (logging) log.v("initialTagOctet: tag number $initialOctetTagNumber, tag $initialOctetTag")

            val remainder: ArrayList<UByte> = ArrayList(raw.takeLast(raw.size - 1))

            val longTag: Asn1Tag?
            val longTagNumber: ULong?

            // parse long tag if required
            //
            if (initialOctetTag.value == 31.toULong()) {
                // ==> tag coded over one or more subsequent bytes

                val subsequentIdentifierTagBytes: ArrayList<UByte> = arrayListOf()

                // read all tag bytes with MSB set
                //
                while (remainder[0].bitsAreSet(8)) {
                    subsequentIdentifierTagBytes.add(remainder[0])
                    remainder.removeAt(0)
                }

                // then add the next byte
                //
                subsequentIdentifierTagBytes.add(remainder[0])
                remainder.removeAt(0)

                if (logging) log.v("subsequentIdentifierTagBytes (${subsequentIdentifierTagBytes.size}):")
                subsequentIdentifierTagBytes.forEach {
                    if (logging) log.v(it.toString(16))
                }

                val subsequentTag7BitStrings = subsequentIdentifierTagBytes
                    .map { it.toString(radix = 2).padStart(8, '0').takeLast(7) }

                if (logging) log.v("subsequentTag7BitStrings:")
                subsequentTag7BitStrings.forEach {
                    if (logging) log.v(it)
                }

                val tagBits = subsequentTag7BitStrings.joinToString("")

                if (logging) log.v("tagBits, $tagBits")

                val tagBitsPackedToNearestByte =
                    if (tagBits.length % 8 == 0)
                        tagBits
                    else
                        "0".repeat(8 - (tagBits.length % 8)) + tagBits

                if (logging) log.v("tagBitsPackedToNearestByte, $tagBitsPackedToNearestByte")

                longTagNumber = tagBitsPackedToNearestByte.toULong(radix = 2)
                if (logging) log.v("tagNumber $longTagNumber")

                longTag = Asn1Tag.fromValue(longTagNumber)
                if (logging) log.v(longTag.toString())
            } else {
                longTag = null
                longTagNumber = null
            }

            val tagNumber = longTagNumber ?: initialOctetTagNumber
            val tag = longTag ?: initialOctetTag

            // parse length bytes

            val firstLengthByte = remainder[0]
            remainder.removeAt(0)

            val longFormLength = firstLengthByte.bitsAreSet(8)

            if (logging) log.v(if (longFormLength) "long form length" else "short form length")

            val length: ULong = if (!longFormLength) {
                firstLengthByte.getStandAloneBitsValue(1,2,3,4,5,6,7).toULong()
            } else {
                val numberOfSubsequentLengthBytes = firstLengthByte.getStandAloneBitsValue(1,2,3,4,5,6,7).toInt()

                if (logging) log.v("tag length is coded on $numberOfSubsequentLengthBytes subsequent length bytes")

                val lengthBytes = remainder.take(numberOfSubsequentLengthBytes)

                for (i in 1..numberOfSubsequentLengthBytes) {
                    remainder.removeAt(0)
                }

                lengthBytes
                    .map { it.toString(16).padStart(2, '0') }
                    .joinToString("")
                    .toULong(16)
            }

            if (logging) log.v("length $length")

            log.v("class: $idClass, construction: $construction, tag number: $tagNumber, tag: $tag")

            val content = remainder.take(length.toInt())
            val contentHex = content.joinToString(separator = "", transform = { it.toString(16).padStart(2, '0') })

            for (i in 1..length.toInt())
                remainder.removeAt(0)

            if (construction == Asn1Construction.Constructed) {
                if (logging) log.v("parsing next layer of constructed element")
                if (logging) log.v("-".repeat(60))
                parse(contentHex)
            } else {
                if (logging) log.v("content: $contentHex")

                if (initialOctetTag == Asn1Tag.object_identifier) {
                    parseOID(contentHex.hexToUBytes())
                }
            }

            if (logging) log.v("=".repeat(60))
            if (remainder.isNotEmpty()) {
                parse(remainder.joinToString(separator = "", transform = { it.toString(16).padStart(2, '0') }))
            }
        }
    }
}