package dev.aster.guard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Interpretable heuristics, NOT a malware verdict.
 * Signals indicate declared capabilities, not verified malicious behavior.
 */
public final class RiskEngine {
    private RiskEngine() {}

    public static final class Signals {
        public boolean system, debuggable, oldTarget, canInstallPackages, overlay,
            accessibilityService, deviceAdmin, internet, readsSms, receivesSms,
            readsCallLog, readsContacts, readsNotifications, signerChanged;
        public int unprotectedExported;
    }

    public static final class Assessment {
        public final int score;
        public final List<String> reasons;
        private Assessment(int score, List<String> reasons) {
            this.score = score;
            this.reasons = Collections.unmodifiableList(reasons);
        }
    }

    public static Assessment assess(Signals s) {
        int score = 0;
        List<String> why = new ArrayList<>();
        if (s.system) return new Assessment(0, why);
        if (s.signerChanged) {
            score += 65;
            why.add("Подпись отличается от сохранённой ранее — проверьте обновление и источник установки.");
        }
        if (s.debuggable) {
            score += 15;
            why.add("Приложение собрано с включённой отладкой.");
        }
        if (s.oldTarget) {
            score += 8;
            why.add("Устаревшая целевая версия Android может ослаблять системные ограничения.");
        }
        if (s.canInstallPackages) {
            score += 12;
            why.add("Запрашивает установку других APK.");
        }
        if (s.overlay) {
            score += 12;
            why.add("Запрашивает возможность отображаться поверх других окон.");
        }
        if (s.accessibilityService) {
            score += 16;
            why.add("Содержит службу специальных возможностей (не обязательно включённую).");
        }
        if (s.deviceAdmin) {
            score += 12;
            why.add("Содержит компонент администратора устройства.");
        }
        if (s.readsSms && s.receivesSms && s.internet) {
            score += 16;
            why.add("Сочетает доступ к SMS с доступом в интернет.");
        }
        if (s.readsCallLog && s.internet) {
            score += 13;
            why.add("Сочетает доступ к журналу звонков с доступом в интернет.");
        }
        if (s.readsNotifications && s.internet) {
            score += 8;
            why.add("Служба уведомлений потенциально может читать уведомления при включении.");
        }
        if (s.overlay && s.accessibilityService) {
            score += 23;
            why.add("Сочетание наложения окон и службы специальных возможностей требует проверки.");
        }
        if (s.canInstallPackages && s.accessibilityService) {
            score += 12;
            why.add("Совместно заявлены установка APK и возможности управления интерфейсом.");
        }
        if (s.unprotectedExported >= 7) {
            score += 8;
            why.add("Много экспортированных компонентов без обязательных разрешений.");
        }
        return new Assessment(Math.min(score, 100), why);
    }
}
