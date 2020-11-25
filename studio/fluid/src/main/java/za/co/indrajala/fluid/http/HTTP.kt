package za.co.indrajala.fluid.http

import com.google.gson.Gson
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import za.co.indrajala.fluid.log
import java.io.IOException

class HTTP {
    companion object {

        private val ContentTypeJSON = "application/json; charset=utf-8".toMediaTypeOrNull()!!

        private val client = OkHttpClient()

        // http://192.168.8.103:8777/

        private var protocol = "!not configured!"
        private var host = "!not configured!"
        private var port = 0

        private val logging = true

        fun configure(
            protocol: String,
            host: String,
            port: Int
        ) {
            this.protocol = protocol
            this.host = host
            this.port = port
        }

        val urlBase: String
            get() = "$protocol://$host:$port"

        fun post(path: String, payload: Any, callback: (json: String?, error: Boolean) -> Unit) {

            val jsonRequest = Gson().toJson(payload)
            val url = "$urlBase$path"

            val callBacks = object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    e.printStackTrace()

                    if (logging) {
                        log.e("POST RQ", e)
                    }


                    callback(null, true)
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {

                        // TODO check content-type = application/json

                        val jsonResponse = response.body?.string()

                        if (logging) {
                            log.v("rsp to POST from $url: $jsonResponse")
                        }

                        callback(jsonResponse, false)
                    }
                }
            }

            if (logging) {
                log.v("POST to $url: $jsonRequest")
            }

            val call: Call = client.newCall(
                Request.Builder()
                    .url(url)
                    .post(jsonRequest.toRequestBody(ContentTypeJSON))
                    .build()
            )
            call.enqueue(callBacks)
        }
    }
}