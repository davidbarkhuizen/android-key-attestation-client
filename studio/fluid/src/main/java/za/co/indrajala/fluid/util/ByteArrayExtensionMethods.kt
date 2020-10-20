package za.co.indrajala.fluid.util

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }