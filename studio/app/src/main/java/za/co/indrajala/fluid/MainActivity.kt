package za.co.indrajala.fluid

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import za.co.indrajala.fluid.util.log

class MainActivity : AppCompatActivity() {

    var fluid: Fluid? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        try {
            if (fluid == null) {
                fluid = Fluid().init()
            }
        } catch (e: Exception) {
            log.v(e.toString())
        }
    }

    fun onClick(view: android.view.View ) {
        try {
            fluid?.test()
        } catch (e: Exception) {
            log.v(e.toString())
        }
    }
}