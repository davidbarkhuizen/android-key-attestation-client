package za.co.indrajala.fluid.attestation.enums

import com.google.gson.annotations.SerializedName

enum class Algorithm(val value: Int) {

    @SerializedName("1")
    RSA(1),

    @SerializedName("3")
    EC(3),

    @SerializedName("32")
    AES(32),

    @SerializedName("128")
    HMAC(128);

    companion object {
        private val map = Algorithm.values().associateBy(Algorithm::value)
        fun fromValue(value: Int): Algorithm {
            return map[value] ?: error("$value")
        }
    }
}