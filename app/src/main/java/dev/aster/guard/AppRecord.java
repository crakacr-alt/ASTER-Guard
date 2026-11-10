package dev.aster.guard;

import java.util.ArrayList;
import java.util.List;

/** Immutable-by-convention snapshot: the scanner owns writes, UI reads after publication. */
public final class AppRecord {
    public String label = "";
    public String packageName = "";
    public String installer = "Неизвестен";
    public String version = "";
    public String apkPath = "";
    public String signerSha256 = "";
    public int uid, targetSdk, score, exportedComponents, unprotectedExported;
    public boolean system, debuggable;
    public long installedAt, updatedAt, apkSize;
    public final List<String> requestedPermissions = new ArrayList<>();
    public final List<String> grantedPermissions = new ArrayList<>();
    public final List<String> reasons = new ArrayList<>();
    public final List<String> observations = new ArrayList<>();

    public String riskLabel() {
        if (score >= 70) return "Высокий риск";
        if (score >= 35) return "Повышенный риск";
        if (score >= 15) return "Требует внимания";
        return "Низкий риск";
    }
}
