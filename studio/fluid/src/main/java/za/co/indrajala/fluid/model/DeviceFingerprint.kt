package za.co.indrajala.fluid.model

import android.os.Build
import android.provider.Settings
import android.content.Context

data class DeviceFingerprint (
    val apiLevel: Int,
    val androidID: String
) {
    override fun toString() =
        "API Level $apiLevel\nAndroid ID $androidID"

    companion object {
        fun print(context: Context): DeviceFingerprint {

            return DeviceFingerprint(
                Build.VERSION.SDK_INT,
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            )
        }
    }
}