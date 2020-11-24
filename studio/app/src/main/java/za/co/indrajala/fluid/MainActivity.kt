package za.co.indrajala.fluid

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.TextView

class MainActivity : AppCompatActivity() {

    private val host = "192.168.8.105"
    private val port = 8777

    var fluid = Fluid(host, port)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val hostView = findViewById<TextView>(R.id.hostLabel) as TextView
        hostView.text = "$host:$port"
    }

    fun onClick(view: View) {
        try {
            fluid.generateAndAttestKey(applicationContext)
        } catch (e: Exception) {
            log.e("device registration", e)
        }
    }
}