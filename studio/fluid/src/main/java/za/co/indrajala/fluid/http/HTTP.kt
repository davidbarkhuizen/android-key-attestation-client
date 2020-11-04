package za.co.indrajala.fluid.http

import com.google.gson.Gson
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import za.co.indrajala.fluid.log
import java.io.IOException

class HTTP {
    companion object {

        enum class LogLevel {
            Off,
            On,
            Verbose
        }

        private val ContentTypeJSON = "application/json; charset=utf-8".toMediaTypeOrNull()!!

        private val client = OkHttpClient()

        // http://192.168.8.103:8777/

        private var protocol = "!not configured!"
        private var host = "!not configured!"
        private var port = 0

        private var logLevel = LogLevel.Off

        fun configure(
            protocol: String,
            host: String,
            port: Int,
            logLevel: LogLevel = LogLevel.Off
        ) {
            this.protocol = protocol
            this.host = host
            this.port = port

            this.logLevel = logLevel
        }

        val urlBase: String
            get() = "$protocol://$host:$port"

        fun post(path: String, payload: Any, callback: (json: String?) -> Unit) {

            val jsonRequest = Gson().toJson(payload)
            val url = "$urlBase$path"

            val callBacks = object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    e.printStackTrace()

                    when (logLevel) {
                        LogLevel.On, LogLevel.Verbose -> log.e("POST RQ", e)
                        else -> Unit
                    }

                    callback(null)
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {

                        // TODO check content-type = application/json

                        val jsonResponse = response.body?.string()

                        when (logLevel) {
                            LogLevel.On, LogLevel.Verbose -> log.v("POST RSP: $url")
                            else -> Unit
                        }
                        when (logLevel) {
                            LogLevel.Verbose -> log.v("RSP payload: $jsonResponse")
                            else -> Unit
                        }

                        callback(jsonResponse)
                    }
                }
            }

            when (logLevel) {
                LogLevel.On, LogLevel.Verbose -> log.v("POST: $url")
                else -> Unit
            }
            when (logLevel) {
                LogLevel.Verbose -> log.v("RQ payload: $jsonRequest")
                else -> Unit
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