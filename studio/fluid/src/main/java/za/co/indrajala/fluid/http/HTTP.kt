package za.co.indrajala.fluid.http

import com.google.gson.Gson
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import za.co.indrajala.fluid.log
import java.io.IOException

class HTTP {
    companion object {

        private val JSON = "application/json; charset=utf-8".toMediaTypeOrNull()!!

        private val client = OkHttpClient()

        // http://192.168.8.103:8777/

        private var protocol = "!not configured!"
        private var host = "!not configured!"

        fun configure(
            protocol: String,
            host: String
        ) {
            this.protocol = protocol
            this.host = host
        }

        val urlBase: String
            get() = "$protocol://$host"

        fun post(path: String, payload: Any, callback: (json: String?) -> Unit) {

            val json = Gson().toJson(payload)

            val callBacks = object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    e.printStackTrace()
                    log.e("HTTP", e)
                    callback(null)
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        log.v("POST rsp: ${response.body!!.string()}")
                        callback(response.body.toString())
                    }
                }
            }

            val call: Call = client.newCall(
                Request.Builder()
                    .url("$urlBase$path")
                    .post(json.toRequestBody(JSON))
                    .build()
            )
            call.enqueue(callBacks)
        }
    }
}