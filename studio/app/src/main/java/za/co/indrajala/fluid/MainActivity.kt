package za.co.indrajala.fluid

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View

class MainActivity : AppCompatActivity() {

    var fluid = Fluid("192.168.8.104", 8777)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }

    fun onClick(view: View) {
        try {
            fluid.generateAndAttestKey(applicationContext)
        } catch (e: Exception) {
            log.e("device registration", e)
        }
    }
}