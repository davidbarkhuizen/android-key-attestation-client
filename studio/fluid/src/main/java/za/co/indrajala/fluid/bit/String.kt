package za.co.indrajala.fluid.bit

fun String.hexToUBytes (): UByteArray =
    this
        .chunked(2)
        .map { it.toUByte(16) }
        .toUByteArray()