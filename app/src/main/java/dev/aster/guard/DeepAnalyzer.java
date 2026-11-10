package dev.aster.guard;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Opt-in APK archive inspection. Never executes or extracts foreign code. */
public final class DeepAnalyzer {
    public static final class Result {
        public String sha256 = "";
        public final List<String> notes = new ArrayList<>();
        public int entries, extraDex, embeddedArchives, nativeLibraries;
    }

    private DeepAnalyzer() {}
    public static Result inspect(String apkPath) throws IOException {
        File apk = new File(apkPath);
        if (!apk.isFile()) throw new IOException("APK недоступен для чтения на этой версии Android");
        Result result = new Result();
        result.sha256 = Hashing.fileSha256(apk);
        try (ZipFile zip = new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> e = zip.entries();
            while (e.hasMoreElements() && result.entries < 20000) {
                if (Thread.currentThread().isInterrupted()) throw new IOException("Анализ остановлен");
                ZipEntry entry = e.nextElement();
                result.entries++;
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (name.startsWith("lib/") && name.endsWith(".so")) result.nativeLibraries++;
                if ((name.startsWith("assets/") || name.startsWith("res/raw/")) &&
                    (name.endsWith(".apk") || name.endsWith(".jar") || name.endsWith(".dex"))) {
                    result.embeddedArchives++;
                    if (result.notes.size() < 8) result.notes.add("Вложенный исполняемый архив: " + entry.getName());
                }
                if (name.startsWith("classes") && name.endsWith(".dex") && !name.equals("classes.dex"))
                    result.extraDex++;
            }
        }
        if (result.entries >= 20000) result.notes.add("Превышен лимит записей — архив требует отдельной проверки.");
        if (result.embeddedArchives == 0) result.notes.add("Встроенных APK/DEX/JAR в assets и res/raw не обнаружено.");
        result.notes.add("Дополнительные classes*.dex: " + result.extraDex + " (обычно нормальный multidex).");
        result.notes.add("Нативных библиотек: " + result.nativeLibraries + ".");
        result.notes.add("Наличие вложенного кода само по себе не доказывает заражение.");
        return result;
    }
}
