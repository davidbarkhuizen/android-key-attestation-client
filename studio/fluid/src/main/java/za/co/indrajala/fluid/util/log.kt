package za.co.indrajala.fluid.util

class log {
    companion object {
        private const val ANDROID_LOG_TAG = "fluid.log"

        fun v(s: String) {
            android.util.Log.v(ANDROID_LOG_TAG, s)
        }

        fun v(label: String, text: String) {
            v("$label: $text")
        }

        fun v(label: String, number: Int) {
            v("$label: $number")
        }

        fun v(label: String, predicate: Boolean) {
            v("$label: $predicate")
        }
    }
}