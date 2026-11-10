package dev.aster.guard;

import android.Manifest;
import android.content.Context;
import android.content.pm.*;
import android.os.Build;
import android.content.SharedPreferences;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/** Explicit foreground user-initiated metadata scan; no background service. */
public final class Scanner {
    public interface Progress { void onProgress(int completed, int total); }
    private Scanner() {}

    public static List<AppRecord> scan(Context context, AtomicBoolean cancelled, Progress progress) {
        PackageManager pm = context.getPackageManager();
        long flags = PackageManager.GET_PERMISSIONS |
            PackageManager.GET_ACTIVITIES | PackageManager.GET_RECEIVERS |
            PackageManager.GET_SERVICES | PackageManager.GET_PROVIDERS |
            (Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
        List<PackageInfo> packages;
        if (Build.VERSION.SDK_INT >= 33) {
            packages = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags));
        } else {
            packages = pm.getInstalledPackages((int) flags);
        }
        SharedPreferences baseline = context.getSharedPreferences("signature_baseline", Context.MODE_PRIVATE);
        SharedPreferences.Editor updates = baseline.edit();
        List<AppRecord> out = new ArrayList<>(packages.size());
        int i = 0;
        for (PackageInfo p : packages) {
            if (cancelled.get() || Thread.currentThread().isInterrupted()) break;
            try {
                AppRecord r = inspect(pm, p, baseline, updates);
                out.add(r);
            } catch (Exception e) {
                AppRecord r = new AppRecord();
                r.packageName = p.packageName;
                r.label = p.packageName;
                r.observations.add("Не удалось прочитать метаданные: " + e.getClass().getSimpleName());
                out.add(r);
            }
            i++;
            if (i % 8 == 0 || i == packages.size()) progress.onProgress(i, packages.size());
        }
        if (!cancelled.get()) updates.apply();
        Collections.sort(out, new Comparator<AppRecord>() {
            @Override public int compare(AppRecord a, AppRecord b) {
                int risk = Integer.compare(b.score, a.score);
                return risk != 0 ? risk : a.label.compareToIgnoreCase(b.label);
            }
        });
        return out;
    }

    private static AppRecord inspect(PackageManager pm, PackageInfo p, SharedPreferences baseline,
                                      SharedPreferences.Editor updates) throws Exception {
        AppRecord r = new AppRecord();
        r.packageName = p.packageName;
        ApplicationInfo ai = p.applicationInfo;
        r.label = ai == null ? p.packageName : String.valueOf(pm.getApplicationLabel(ai));
        r.uid = ai == null ? -1 : ai.uid;
        r.targetSdk = ai == null ? 0 : ai.targetSdkVersion;
        r.system = ai != null && (ai.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
        r.debuggable = ai != null && (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        r.apkPath = ai == null ? "" : ai.sourceDir;
        r.apkSize = r.apkPath.isEmpty() ? 0 : new File(r.apkPath).length();
        r.installedAt = p.firstInstallTime;
        r.updatedAt = p.lastUpdateTime;
        r.version = p.versionName == null ? "—" : p.versionName;
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                InstallSourceInfo source = pm.getInstallSourceInfo(p.packageName);
                String installer = source.getInstallingPackageName();
                r.installer = installer == null ? "Неизвестен / локально" : installer;
            } else {
                String installer = pm.getInstallerPackageName(p.packageName);
                r.installer = installer == null ? "Неизвестен / локально" : installer;
            }
        } catch (Exception ignored) { r.installer = "Недоступен"; }

        if (p.requestedPermissions != null) {
            for (int idx = 0; idx < p.requestedPermissions.length; idx++) {
                String perm = p.requestedPermissions[idx];
                r.requestedPermissions.add(perm);
                int flag = p.requestedPermissionsFlags != null && idx < p.requestedPermissionsFlags.length
                    ? p.requestedPermissionsFlags[idx] : 0;
                if ((flag & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) r.grantedPermissions.add(perm);
            }
        }
        r.exportedComponents = countExported(p);
        r.unprotectedExported = countUnprotected(p);
        RiskEngine.Signals s = new RiskEngine.Signals();
        s.system = r.system;
        s.debuggable = r.debuggable;
        s.oldTarget = r.targetSdk > 0 && r.targetSdk < 28 && Build.VERSION.SDK_INT >= 33;
        s.internet = has(r, Manifest.permission.INTERNET);
        s.canInstallPackages = has(r, Manifest.permission.REQUEST_INSTALL_PACKAGES);
        s.overlay = has(r, Manifest.permission.SYSTEM_ALERT_WINDOW);
        s.readsSms = granted(r, Manifest.permission.READ_SMS);
        s.receivesSms = granted(r, Manifest.permission.RECEIVE_SMS);
        s.readsCallLog = granted(r, Manifest.permission.READ_CALL_LOG);
        s.readsContacts = granted(r, Manifest.permission.READ_CONTACTS);
        s.unprotectedExported = r.unprotectedExported;
        if (p.services != null) for (ServiceInfo service : p.services) {
            if (Manifest.permission.BIND_ACCESSIBILITY_SERVICE.equals(service.permission)) s.accessibilityService = true;
            if (Manifest.permission.BIND_NOTIFICATION_LISTENER_SERVICE.equals(service.permission)) s.readsNotifications = true;
        }
        if (p.receivers != null) for (ActivityInfo receiver : p.receivers) {
            if (Manifest.permission.BIND_DEVICE_ADMIN.equals(receiver.permission)) s.deviceAdmin = true;
        }
        byte[] sig = signature(p);
        if (sig != null) {
            r.signerSha256 = Hashing.sha256(sig);
            String old = baseline.getString("sig:" + r.packageName, null);
            s.signerChanged = old != null && !old.equals(r.signerSha256);
            updates.putString("sig:" + r.packageName, r.signerSha256);
        }
        RiskEngine.Assessment risk = RiskEngine.assess(s);
        r.score = risk.score;
        r.reasons.addAll(risk.reasons);
        if (!r.system && r.installer.startsWith("Неизвестен")) {
            r.observations.add("Не определён установщик — это не доказательство вредоносности.");
        }
        if (r.exportedComponents > 0) {
            r.observations.add("Экспортированных компонентов: " + r.exportedComponents + ", без разрешений: " + r.unprotectedExported + ".");
        }
        return r;
    }

    private static byte[] signature(PackageInfo p) {
        if (Build.VERSION.SDK_INT >= 28) {
            if (p.signingInfo == null) return null;
            Signature[] signatures = p.signingInfo.hasMultipleSigners()
                ? p.signingInfo.getApkContentsSigners()
                : p.signingInfo.getSigningCertificateHistory();
            return signatures == null || signatures.length == 0 ? null : signatures[signatures.length-1].toByteArray();
        }
        return p.signatures == null || p.signatures.length == 0 ? null : p.signatures[0].toByteArray();
    }
    private static boolean has(AppRecord r, String perm) { return r.requestedPermissions.contains(perm); }
    private static boolean granted(AppRecord r, String perm) { return r.grantedPermissions.contains(perm); }
    private static int countExported(PackageInfo p) {
        int n = 0;
        if (p.activities != null) for (ActivityInfo x : p.activities) if (x.exported) n++;
        if (p.receivers != null) for (ActivityInfo x : p.receivers) if (x.exported) n++;
        if (p.services != null) for (ServiceInfo x : p.services) if (x.exported) n++;
        if (p.providers != null) for (ProviderInfo x : p.providers) if (x.exported) n++;
        return n;
    }
    private static int countUnprotected(PackageInfo p) {
        int n = 0;
        if (p.activities != null) for (ActivityInfo x : p.activities) if (x.exported && x.permission == null) n++;
        if (p.receivers != null) for (ActivityInfo x : p.receivers) if (x.exported && x.permission == null) n++;
        if (p.services != null) for (ServiceInfo x : p.services) if (x.exported && x.permission == null) n++;
        if (p.providers != null) for (ProviderInfo x : p.providers) if (x.exported && x.readPermission == null && x.writePermission == null) n++;
        return n;
    }
}
