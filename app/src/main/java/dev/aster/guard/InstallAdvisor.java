package dev.aster.guard;

import java.util.Locale;

/** Pure, non-executing installer diagnostic rules. Never claims ADB fixes minSdk. */
public final class InstallAdvisor {
    private InstallAdvisor(){}

    public static final class Advice {
        public final String code,summary,remedy;
        public final boolean legacyTargetBypass;
        Advice(String code,String summary,String remedy,boolean legacyTargetBypass){
            this.code=code;this.summary=summary;this.remedy=remedy;
            this.legacyTargetBypass=legacyTargetBypass;
        }
    }

    /** Android 14 introduced low-target block, Android 15 raised it. */
    public static int minimumAllowedTarget(int deviceApi){
        if(deviceApi>=35)return 24;
        if(deviceApi>=34)return 23;
        return 0;
    }
    public static Advice preflight(int deviceApi,int minSdk,int targetSdk){
        if(minSdk>deviceApi)return new Advice(
            "INSTALL_FAILED_OLDER_SDK",
            "Приложение требует Android API "+minSdk+", устройство API "+deviceApi+".",
            "Параметр ADB не добавляет отсутствующие Android API. Нужна более новая гостевая Android либо пересборка исходного проекта с проверкой совместимости. --force-sdk НЕ решает эту ошибку.",false);
        int limit=minimumAllowedTarget(deviceApi);
        if(targetSdk>0&&targetSdk<limit)return new Advice(
            "INSTALL_FAILED_DEPRECATED_SDK_VERSION",
            "targetSdk "+targetSdk+" ниже минимально разрешённого "+limit+".",
            "В Android 14+ для лабораторной установки через ADB/Shizuku можно попробовать --bypass-low-target-sdk-block. Старые приложения могут обходить современные ограничения безопасности.",true);
        return new Advice("READY","Явных препятствий по minSdk/targetSdk не найдено.",
            "Это предварительная проверка. Подпись, ABI, split APK, ограничения производителя и свободное место могут заблокировать установку.",false);
    }

    public static Advice failure(String log){
        String s=log==null?"":log.toUpperCase(Locale.ROOT);
        if(s.contains("INSTALL_FAILED_OLDER_SDK"))
            return new Advice("INSTALL_FAILED_OLDER_SDK","Несовместимый minSdk.",
                "Параметрами ADB обычно не исправить. Выберите более новую версию Android для анализа или пересоберите совместимое приложение из исходников.",false);
        if(s.contains("INSTALL_FAILED_DEPRECATED_SDK_VERSION"))
            return new Advice("INSTALL_FAILED_DEPRECATED_SDK_VERSION","Слишком старый targetSdk.",
                "На поддерживаемых версиях Android используйте --bypass-low-target-sdk-block только после подтверждения риска.",true);
        if(s.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE")||s.contains("INSTALL_PARSE_FAILED_INCONSISTENT_CERTIFICATES"))
            return new Advice("SIGNATURE_MISMATCH","Подпись обновления не совпадает с уже установленной.",
                "Новый собственный ключ не является ключом исходного автора. Без исходного ключа нельзя безопасно обновить приложение поверх старого. Сначала сохраните данные; удаление старой версии удалит её данные.",false);
        if(s.contains("INSTALL_FAILED_NO_MATCHING_ABIS"))
            return new Advice("ABI_MISMATCH","Нет библиотек для архитектуры устройства.",
                "Нужна APK-сборка для подходящей ABI или гостевой эмулятор соответствующей архитектуры. Флаг --abi не создаёт отсутствующие .so.",false);
        if(s.contains("INSTALL_FAILED_MISSING_SPLIT"))
            return new Advice("MISSING_SPLITS","Не хватает обязательных split APK.",
                "Установите полный набор APK из того же комплекта через install-multiple/сессию. Одиночный base.apk может быть недостаточен.",false);
        if(s.contains("INSTALL_FAILED_VERSION_DOWNGRADE"))
            return new Advice("VERSION_DOWNGRADE","Версия ниже установленной.",
                "В некоторых отладочных случаях ADB -d работает, но может не поддерживаться производственной сборкой. Рекомендуется устанавливать корректную версию.",false);
        if(s.contains("INSTALL_FAILED_TEST_ONLY"))
            return new Advice("TEST_ONLY","APK помечен как testOnly.",
                "Для тестовой сборки ADB предлагает ключ -t. Используйте только собственный или авторизованный тестовый APK.",false);
        if(s.contains("INSTALL_FAILED_INSUFFICIENT_STORAGE"))
            return new Advice("LOW_STORAGE","Не хватает свободного места.",
                "Освободите место на устройстве; обходного параметра нет.",false);
        if(s.contains("INSTALL_FAILED_VERIFICATION_FAILURE")||s.contains("INSTALL_FAILED_BLOCKED"))
            return new Advice("SECURITY_POLICY","Системная проверка или политика заблокировала APK.",
                "Не отключайте Play Protect или корпоративные политики. Проанализируйте APK и обратитесь к администратору.",false);
        if(s.contains("INSTALL_PARSE_FAILED")||s.contains("INSTALL_FAILED_INVALID_APK"))
            return new Advice("INVALID_APK","APK повреждён или некорректно собран.",
                "Проверьте ZIP/AndroidManifest.xml и подпись; пересоберите из доверенного проекта.",false);
        if(s.contains("SUCCESS"))return new Advice("INSTALLED","Установка завершилась успешно.",
            "Проверьте разрешения и запускайте только доверенные APK.",false);
        return new Advice("UNKNOWN","Нужны подробности ошибки установщика.",
            "Скопируйте полный вывод Shizuku/ADB. Установка не гарантирована даже при корректном SDK.",false);
    }
}
