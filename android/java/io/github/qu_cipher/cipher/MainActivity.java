package io.github.qu_cipher.cipher;

import android.app.NativeActivity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.view.HapticFeedbackConstants;

/**
 * The app's window: a NativeActivity running libcipher_client.so (android_main). The vpn*
 * methods and haptic() are called from Rust (src/android.rs) on its own threads.
 */
public class MainActivity extends NativeActivity {
    private static final int VPN_REQUEST = 1;

    /** 1 = allowed, 0 = waiting for the user, -1 = refused. */
    private static volatile int consent;

    /** Asks for the VPN permission (Android's dialog, the first time) and starts the service. */
    public int vpnPrepare() {
        startService(new Intent(this, CipherVpnService.class));
        Intent request = VpnService.prepare(this);
        if (request == null) {
            consent = 1;
            return 1;
        }
        consent = 0;
        runOnUiThread(() -> startActivityForResult(request, VPN_REQUEST));
        return 0;
    }

    public int vpnConsent() {
        return consent;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == VPN_REQUEST) {
            consent = resultCode == RESULT_OK ? 1 : -1;
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    /** The TUN's fd (still owned by the service), -2 while the service is starting, -1 on error. */
    public int vpnEstablish(String spec) {
        CipherVpnService service = CipherVpnService.instance;
        return service == null ? -2 : service.establish(spec);
    }

    public String vpnError() {
        return CipherVpnService.error;
    }

    public int vpnRevoked() {
        return CipherVpnService.revoked ? 1 : 0;
    }

    /** A short tick as touch feedback (no VIBRATE permission needed); 0 always. */
    public int haptic() {
        int effect = Build.VERSION.SDK_INT >= 30 ? HapticFeedbackConstants.CONFIRM : HapticFeedbackConstants.LONG_PRESS;
        runOnUiThread(() -> getWindow().getDecorView().performHapticFeedback(effect));
        return 0;
    }

    public int vpnStop() {
        CipherVpnService service = CipherVpnService.instance;
        if (service != null) {
            service.shutdown();
        }
        return 0;
    }
}
