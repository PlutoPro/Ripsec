package io.github.plutopro.ripsec.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * Gives the Rust code what only Android can: the virtual interface, and sockets that stay
 * outside it. Everything about the protocol happens in Rust.
 */
class RipsecVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val directory = intent?.getStringExtra(EXTRA_DIRECTORY)
        if (directory == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        showNotification()
        Native.start(this, directory)
        return START_NOT_STICKY
    }

    /** Another VPN took over, or the user withdrew the permission in system settings. */
    override fun onRevoke() {
        Thread { Native.stop() }.start()
        super.onRevoke()
    }

    /**
     * Called from the Rust thread. Returns the interface's file descriptor, which the caller
     * then owns and closes, or -1.
     */
    @Suppress("unused")
    fun establish(address: String, routes: Array<String>, dns: Array<String>, mtu: Int): Int {
        return try {
            val builder = Builder().setSession("Ripsec").setMtu(mtu).addAddress(address, 32)
            // With no IPv6 address or route, Android blocks IPv6 instead of letting it bypass the VPN.
            for (route in routes) {
                val (network, prefix) = route.split('/')
                builder.addRoute(network, prefix.toInt())
            }
            for (server in dns) builder.addDnsServer(server)
            builder.establish()?.detachFd() ?: -1
        } catch (e: Exception) {
            Log.e(TAG, "cannot create the VPN interface", e)
            -1
        }
    }

    /** Called from the Rust thread when the connection is over, for whatever reason. */
    @Suppress("unused")
    fun finished() {
        Handler(Looper.getMainLooper()).post {
            @Suppress("DEPRECATION")
            stopForeground(true)
            stopSelf()
        }
    }

    private fun showNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "VPN connection", NotificationManager.IMPORTANCE_LOW))
            Notification.Builder(this, CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE)
        }
        val notification = builder
            .setContentTitle("Ripsec VPN")
            .setContentText("The VPN is on. Tap to manage it.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION, notification)
        }
    }

    companion object {
        const val EXTRA_DIRECTORY = "directory"
        private const val CHANNEL = "ripsec-vpn"
        private const val NOTIFICATION = 1
        private const val TAG = "ripsec"
    }
}
