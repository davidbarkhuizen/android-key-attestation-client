package za.co.indrajala.fluid

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle

class MainActivity : AppCompatActivity() {

    var fluid: Fluid? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        try {
            if (fluid == null) {
                fluid = Fluid().init(this.applicationContext)
            }
        } catch (e: Exception) {
            log.v(e.toString())
        }
    }

    fun onClick() {
        try {
            fluid?.registerDevice()
        } catch (e: Exception) {
            log.v(e.toString())
        }
    }
}