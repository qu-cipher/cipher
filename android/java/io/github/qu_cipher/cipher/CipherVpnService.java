package io.github.qu_cipher.cipher;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

/**
 * Owns the VPN's TUN. Rust (through MainActivity) builds it from a spec, one setting per line:
 * "address 172.19.0.1 30", "route 0.0.0.0 0", "dns 172.19.0.2", "search example.com", "mtu 1500".
 * The app itself is left out of the VPN, so the engines it runs connect directly.
 */
public class CipherVpnService extends VpnService {
    static volatile CipherVpnService instance;
    static volatile String error = "";
    static volatile boolean revoked;

    private ParcelFileDescriptor tun;

    @Override
    public void onCreate() {
        super.onCreate();
        revoked = false;
        instance = this;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        revoked = true;
        shutdown();
    }

    @Override
    public void onDestroy() {
        closeTun();
        instance = null;
        super.onDestroy();
    }

    synchronized int establish(String spec) {
        try {
            Builder builder = new Builder().setSession("Cipher");
            builder.addDisallowedApplication(getPackageName());
            for (String line : spec.split("\n")) {
                String[] part = line.trim().split(" ");
                switch (part[0]) {
                    case "address": builder.addAddress(part[1], Integer.parseInt(part[2])); break;
                    case "route": builder.addRoute(part[1], Integer.parseInt(part[2])); break;
                    case "dns": builder.addDnsServer(part[1]); break;
                    case "search": builder.addSearchDomain(part[1]); break;
                    case "mtu": builder.setMtu(Integer.parseInt(part[1])); break;
                    default: break;
                }
            }
            // Tapping the system's VPN notice opens the app.
            Intent open = new Intent(this, MainActivity.class);
            builder.setConfigureIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE));

            ParcelFileDescriptor fd = builder.establish();
            if (fd == null) {
                error = "Android didn't allow the VPN";
                return -1;
            }
            // A new TUN (OpenVPN reconnecting) replaces the old one.
            closeTun();
            tun = fd;
            return fd.getFd();
        } catch (PackageManager.NameNotFoundException | RuntimeException e) {
            error = e.getMessage() != null ? e.getMessage() : e.toString();
            return -1;
        }
    }

    synchronized void shutdown() {
        closeTun();
        stopSelf();
    }

    private void closeTun() {
        if (tun != null) {
            try {
                tun.close();
            } catch (java.io.IOException ignored) {
            }
            tun = null;
        }
    }
}
