package za.co.indrajala.fluid.attestation.enums
import com.google.gson.annotations.SerializedName;

enum class Padding(val value: Int) {

    @SerializedName("1")
    NONE(1),

    @SerializedName("2")
    RSA_OAEP(2),

    @SerializedName("3")
    RSA_PSS(3),

    @SerializedName("4")
    RSA_PKCS1_1_5_ENCRYPT(4),

    @SerializedName("5")
    RSA_PKCS1_1_5_SIGN(5),

    @SerializedName("64")
    PKCS7(64);

    companion object {
        private val map = Padding.values().associateBy(Padding::value)
        fun fromValue(value: Int): Padding {
            return map[value] ?: error("$value")
        }
    }
}