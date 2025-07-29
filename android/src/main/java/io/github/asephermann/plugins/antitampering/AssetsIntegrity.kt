package io.github.asephermann.plugins.antitampering

import android.app.Activity
import android.app.AlertDialog
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.res.AssetManager
import android.os.Build
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*


internal object AssetsIntegrity {
    private const val MESSAGE_DIGEST_ALGORITHM = "SHA-256"
    private const val ASSETS_BASE_PATH = "www/"
    private val assetsHashes = Collections.unmodifiableMap(
        HashMap<String, String?>()
    )

    @Throws(Exception::class)
    fun check(activity: Activity, assets: AssetManager, throwExceptionEnabled: Boolean = false): Int {
        val pm: PackageManager = activity.packageManager
        try {
            var msg = ""
            val appInfo: PackageInfo =
                pm.getPackageInfo(activity.packageName, PackageManager.GET_SIGNATURES)
            val sign = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signatures = appInfo.signingInfo?.apkContentsSigners
                signatures?.getOrNull(0)?.toCharsString() ?: ""
            } else {
                @Suppress("DEPRECATION")
                appInfo.signatures?.getOrNull(0)?.toCharsString() ?: ""
            }

            if (sign == "") msg += "App not signed\n"

            for ((key, value) in assetsHashes.entries) {
                val fileNameDecode: ByteArray = Base64.decode(key, 0)
                val fileName = String(fileNameDecode, StandardCharsets.UTF_8)
                val filePath = ASSETS_BASE_PATH + fileName
                val file = assets.open(filePath)
                val hash = getFileHash(file)
                if (value == null || value != hash) {
                    msg += "Content of \"$fileName\" has been tampered\n"
                }
            }
            val alertDialog: AlertDialog = AlertDialog.Builder(activity).create()
            alertDialog.setTitle("Assets Integrity")
            alertDialog.setMessage(msg)
            alertDialog.setButton(
                AlertDialog.BUTTON_POSITIVE, "OK"
            ) { dialog, _ ->
                dialog.dismiss()
                if (msg != "") activity.finish()
                if(throwExceptionEnabled) throw Exception(msg)
            }

            if(msg!="") alertDialog.show()

        } catch (e: java.lang.Exception) {
        }

        return assetsHashes.size
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getFileHash(file: InputStream): String {
        val buffer = ByteArrayOutputStream()
        var nRead: Int
        val data = ByteArray(16384)
        while (file.read(data, 0, data.size).also { nRead = it } != -1) {
            buffer.write(data, 0, nRead)
        }
        buffer.flush()
        val digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM)
        val hashBytes = digest.digest(buffer.toByteArray())
        val hexString = StringBuffer()
        for (i in hashBytes.indices) {
            if (0xff and hashBytes[i].toInt() < 0x10) {
                hexString.append("0")
            }
            hexString.append(Integer.toHexString(0xFF and hashBytes[i].toInt()))
        }
        return String(hexString)
    }
}