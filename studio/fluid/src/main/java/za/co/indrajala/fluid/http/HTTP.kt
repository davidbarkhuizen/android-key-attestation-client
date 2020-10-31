package za.co.indrajala.fluid.http

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import za.co.indrajala.fluid.log
import java.io.IOException

class HTTP {
    companion object {

        private val JSON = "application/json; charset=utf-8".toMediaTypeOrNull()!!

        private val client = OkHttpClient()

        // fun onFailure(call: Call, e: IOException)
        // fun onResponse(call: Call, response: Response)

        fun post(url: String, json: String): Call {

            val request = Request.Builder()
                .url(url)
                .post(json.toRequestBody(JSON))
                .build()

            val callBacks = object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    e.printStackTrace()
                    log.e("HTTP", e)
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        log.v("POST rsp: ${response.body!!.string()}")
                    }
                }
            }

            val call: Call = client.newCall(request)
            call.enqueue(callBacks)
            return call
        }
    }
}