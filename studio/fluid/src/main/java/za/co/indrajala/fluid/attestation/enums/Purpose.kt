package za.co.indrajala.fluid.attestation.enums
import com.google.gson.annotations.SerializedName;

enum class Purpose(val value: Int) {

    @SerializedName("0")
    Encrypt(0),

    @SerializedName("1")
    Decrypt(1),

    @SerializedName("3")
    Sign(2),

    @SerializedName("4")
    Verify(3),

    @SerializedName("4")
    DeriveKey(4),

    @SerializedName("5")
    WrapKey(5);

    companion object {
        private val map = Purpose.values().associateBy(Purpose::value)
        fun fromValue(value: Int): Purpose {
            return map[value] ?: error("$value")
        }
    }
}