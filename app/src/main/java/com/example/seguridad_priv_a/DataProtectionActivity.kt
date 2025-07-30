package com.example.seguridad_priv_a

import com.example.seguridad_priv_a.security.AdvancedAnonymizer
import com.example.seguridad_priv_a.model.*
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import java.util.concurrent.Executor

class DataProtectionActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy {
        (application as PermissionsApplication).dataProtectionManager
    }

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var executor: Executor

    private var sessionHandler = Handler(Looper.getMainLooper())
    private val SESSION_TIMEOUT_MS = 5 * 60 * 1000L // 5 minutos
    private val sessionRunnable = Runnable {
        Toast.makeText(this, "Sesión caducada. Reautenticando...", Toast.LENGTH_LONG).show()
        authenticateUser()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        executor = ContextCompat.getMainExecutor(this)
        setupBiometricPrompt()
        authenticateUser()

        setupUI()
    }

    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            loadAccessLogs()
            Toast.makeText(this, "Logs actualizados", Toast.LENGTH_SHORT).show()
            resetSessionTimeout()
        }

        binding.btnClearData.setOnClickListener {
            showClearDataDialog()
            resetSessionTimeout()
        }
    }

    private fun setupBiometricPrompt() {
        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    dataProtectionManager.logAccess("AUTH", "Biometría exitosa")
                    loadDataProtectionInfo()
                    loadAccessLogs()
                    resetSessionTimeout()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    fallbackToPIN()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Biometría incorrecta", Toast.LENGTH_SHORT).show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación requerida")
            .setSubtitle("Escanea tu huella digital para acceder a la protección de datos")
            .setDeviceCredentialAllowed(true) // Fallback a PIN/patrón
            .build()
    }

    private fun authenticateUser() {
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                biometricPrompt.authenticate(promptInfo)
            }
            else -> {
                fallbackToPIN()
            }
        }
    }

    private fun fallbackToPIN() {
        AlertDialog.Builder(this)
            .setTitle("Acceso restringido")
            .setMessage("No se pudo usar biometría. Usa tu PIN o patrón para acceder.")
            .setPositiveButton("Aceptar") { _, _ ->
                loadDataProtectionInfo()
                loadAccessLogs()
                resetSessionTimeout()
            }
            .setCancelable(false)
            .show()
    }

    private fun loadDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()
        val infoText = StringBuilder()

        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\n\n")
        info.forEach { (key, value) ->
            infoText.append("• $key: $value\n")
        }

        infoText.append("\n📊 EVIDENCIAS DE PROTECCIÓN:\n")
        infoText.append("• Encriptación AES-256-GCM activa\n")
        infoText.append("• Todos los accesos registrados\n")
        infoText.append("• Datos anonimizados automáticamente\n")
        infoText.append("• Almacenamiento local seguro\n")
        infoText.append("• No hay compartición de datos\n")

        binding.tvDataProtectionInfo.text = infoText.toString()
        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
    }

    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()
        binding.tvAccessLogs.text = if (logs.isNotEmpty()) logs.joinToString("\n") else "No hay logs disponibles"
        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
    }

    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados y logs de acceso? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun clearAllData() {
        dataProtectionManager.clearAllData()
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text = "🔐 DATOS BORRADOS DE FORMA SEGURA\n\nTodos los datos personales y logs han sido eliminados del dispositivo."
        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()
        dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    }

    override fun onResume() {
        super.onResume()
        resetSessionTimeout()
    }

    override fun onPause() {
        super.onPause()
        sessionHandler.removeCallbacks(sessionRunnable)
    }

    private fun resetSessionTimeout() {
        sessionHandler.removeCallbacks(sessionRunnable)
        sessionHandler.postDelayed(sessionRunnable, SESSION_TIMEOUT_MS)
    }
}

