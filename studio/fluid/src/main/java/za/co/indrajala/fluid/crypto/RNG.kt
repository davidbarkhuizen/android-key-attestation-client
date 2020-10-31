package za.co.indrajala.fluid.crypto

import java.security.SecureRandom

class RNG {
    companion object {
        private val rng = SecureRandom()

        fun bytes(size: Int): ByteArray {
            val ret = ByteArray(size)
            rng.nextBytes(ret)
            return ret
        }
    }
}