package za.co.indrajala.fluid

class log {
    companion object {
        private const val ANDROID_LOG_TAG = "fluid.log"
        private const val lineLen = 80

        fun v(s: String) =
            s.split("\n")
                .forEach { android.util.Log.v(ANDROID_LOG_TAG, it) }

        fun d(s: String) =
            s.split("\n")
                .forEach { android.util.Log.d(ANDROID_LOG_TAG, it) }

        fun v_rjust(text: String) =
            v("${text}".padStart(lineLen, ' '))

        fun v_header(s: String, dividerLen: Int = lineLen, dividerChar: Char = '-') {
            v("".padStart(dividerLen, dividerChar))
            v_rjust(s.toUpperCase())
        }

        fun v(label: String, text: String) =
            v("$label: $text")

        fun v(label: String, number: Int) =
            v("$label: $number")

        fun v(label: String, predicate: Boolean) =
            v("$label: $predicate")

        fun v(label: String, summary: List<Pair<String, String?>>) {
            v_rjust(label)

            summary
                .filter { it.second != null}
                .forEach { log.v(it.first, it.second ?: "" ) }
        }

        fun d(label: String, text: String) =
            d("$label: $text")

        fun e(label: String, e: Exception) =
            android.util.Log.e(ANDROID_LOG_TAG, label, e)
    }
}