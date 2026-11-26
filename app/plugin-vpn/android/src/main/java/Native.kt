package io.github.plutopro.ripsec.vpn

/** The Rust VPN code, which lives in the application's native library. */
object Native {
    init {
        System.loadLibrary("ripsec_app_lib")
    }

    /** Starts connecting on a thread of its own. The service is called back from it. */
    @JvmStatic
    external fun start(service: RipsecVpnService, directory: String)

    /** Returns once the tunnel is gone. */
    @JvmStatic
    external fun stop()
}
