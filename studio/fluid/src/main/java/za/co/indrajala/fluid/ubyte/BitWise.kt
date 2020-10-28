package za.co.indrajala.fluid.ubyte

fun UByte.toBinary(): String =
    Integer.toBinaryString(this.toInt()).padEnd(8, '0')

//infix inline
fun UByte.shl(shift: Int): UByte {

    //println("base value $this")

    val binary = this.toBinary().reversed()

    //println("binary $binary")

    val rotatedBinary = binary.takeLast(binary.length - shift) + binary.take(shift)

    //println("rotated $rotatedBinary")

    val shifted = rotatedBinary.toUByte(2)

    //println("shifted $shifted")

    return shifted
}

fun UByte.shr(shift: Int): UByte {

    println("base value $this")

    val binary = this.toBinary().reversed()

    println("binary $binary")

    val rotatedBinary = binary.takeLast(shift) + binary.take(binary.length - shift)

    println("rotated $rotatedBinary")

    val shifted = rotatedBinary.toUByte(2)

    println("shifted $shifted")

    return shifted
}