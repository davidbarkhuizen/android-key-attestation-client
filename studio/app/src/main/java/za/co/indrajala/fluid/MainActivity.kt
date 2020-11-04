package za.co.indrajala.fluid

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle

class MainActivity : AppCompatActivity() {

    var fluid = Fluid().init(this.applicationContext)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }

    fun onClick() {
        try {
            fluid.registerDevice()
        } catch (e: Exception) {
            log.e("device registration", e)
        }
    }
}