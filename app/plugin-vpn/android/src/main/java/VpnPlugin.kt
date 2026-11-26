package io.github.plutopro.ripsec.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.provider.OpenableColumns
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.ByteArrayOutputStream

@InvokeArg
class StartArguments {
    lateinit var directory: String
    /** Whether the server is on the local network. */
    var local: Boolean = false
}

private const val MAX_PROFILE = 64 * 1024
// By name, so that building does not depend on the newest SDK's constants.
private const val LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
private const val ANDROID_17 = 37

@TauriPlugin(permissions = [Permission(strings = [LOCAL_NETWORK], alias = "localNetwork")])
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun directory(invoke: Invoke) {
        invoke.resolve(JSObject().put("directory", activity.noBackupFilesDir.absolutePath))
    }

    @Command
    fun start(invoke: Invoke) {
        // Android 17 blocks apps from local addresses until the user allows it.
        val needed = Build.VERSION.SDK_INT >= ANDROID_17 &&
            invoke.parseArgs(StartArguments::class.java).local &&
            activity.checkSelfPermission(LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED
        if (needed) requestPermissionForAlias("localNetwork", invoke, "localNetworkAnswered")
        else askToStart(invoke)
    }

    @PermissionCallback
    fun localNetworkAnswered(invoke: Invoke) {
        if (activity.checkSelfPermission(LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED) askToStart(invoke)
        else invoke.reject("the server is on your local network: allow Ripsec to find nearby devices to reach it")
    }

    private fun askToStart(invoke: Invoke) {
        // Without it the connection still works, but its notification is hidden.
        if (Build.VERSION.SDK_INT >= 33 &&
            activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        // Android shows its own consent dialog the first time.
        val consent = VpnService.prepare(activity)
        if (consent == null) startService(invoke) else startActivityForResult(invoke, consent, "consented")
    }

    @ActivityCallback
    fun consented(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode == Activity.RESULT_OK) startService(invoke)
        else invoke.reject("permission to create a VPN was declined")
    }

    private fun startService(invoke: Invoke) {
        val arguments = invoke.parseArgs(StartArguments::class.java)
        val intent = Intent(activity, RipsecVpnService::class.java)
            .putExtra(RipsecVpnService.EXTRA_DIRECTORY, arguments.directory)
        try {
            if (Build.VERSION.SDK_INT >= 26) activity.startForegroundService(intent)
            else activity.startService(intent)
            invoke.resolve(JSObject())
        } catch (e: Exception) {
            invoke.reject("cannot start the VPN service: ${e.message}")
        }
    }

    @Command
    fun pickProfile(invoke: Invoke) {
        // Profiles have no registered type, so every file is offered; the content is checked.
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("*/*")
        startActivityForResult(invoke, intent, "picked")
    }

    @ActivityCallback
    fun picked(invoke: Invoke, result: ActivityResult) {
        val uri = result.data?.data
        if (result.resultCode != Activity.RESULT_OK || uri == null) {
            invoke.resolve(JSObject())
            return
        }
        try {
            val bytes = ByteArrayOutputStream()
            activity.contentResolver.openInputStream(uri)!!.use { input ->
                val buffer = ByteArray(4096)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    bytes.write(buffer, 0, read)
                    require(bytes.size() <= MAX_PROFILE) { "that file is too large to be a profile" }
                }
            }
            var name = "profile"
            activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                if (it.moveToFirst()) name = it.getString(0)
            }
            invoke.resolve(JSObject().put("name", name).put("text", bytes.toString("UTF-8")))
        } catch (e: Exception) {
            invoke.reject("cannot read the file: ${e.message}")
        }
    }
}
