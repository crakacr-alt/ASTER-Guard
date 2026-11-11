package dev.aster.guard;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.util.ReferenceUtil;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Read-only privacy/security DEX CALL-SITE analyzer.
 * A bytecode reference is evidence of a possible code path, NEVER proof of execution.
 * Does not execute untrusted code, disable licensing, or alter APKs.
 */
public final class PrivacyCodeAnalyzer {
    public static final class Rule {
        public final String id,label,details;
        Rule(String id,String label,String details){this.id=id;this.label=label;this.details=details;}
    }
    public static final class Evidence {
        public final String rule,method,reference;
        Evidence(String rule,String method,String reference){
            this.rule=rule;this.method=method;this.reference=reference;
        }
    }
    public static final class Report {
        public final Map<String,Integer> sdkPackages=new LinkedHashMap<>();
        public final Map<String,Integer> ruleCounts=new LinkedHashMap<>();
        public final List<Evidence> evidence=new ArrayList<>();
        public final List<String> warnings=new ArrayList<>();
        public int dexFiles,classes,methods,inspectedInstructions;
        public boolean limited;
        public String summary(){
            return "DEX: "+dexFiles+" · классов: "+classes+" · методов: "+methods+
              " · инструкций: "+inspectedInstructions+" · найденных ссылок: "+evidence.size()+
              (limited?" · анализ ограничен":"");
        }
    }
    static final Rule[] RULES={
        new Rule("ad-id","Рекламный идентификатор","Обнаружена ссылка на Advertising ID. Использование по назначению нужно подтвердить."),
        new Rule("device-id","Идентификатор телефона / SIM","Имеется ссылка на TelephonyManager. Доступ может быть запрещён Android."),
        new Rule("location","Геолокация","Присутствует API получения местоположения. Не доказано, что он вызывается."),
        new Rule("contacts","Контакты или журнал звонков","В коде есть ссылки на соответствующие API или provider."),
        new Rule("sms","SMS","Есть вызов отправки SMS или доступ к провайдеру сообщений."),
        new Rule("microphone","Микрофон","Найдена ссылка на API аудиозаписи."),
        new Rule("camera","Камера","Найдена ссылка на API камеры."),
        new Rule("webview","JavaScript-мост WebView","Проверьте addJavascriptInterface и происхождение загружаемого HTML."),
        new Rule("dynamic-code","Динамическая загрузка DEX","Код может загружать дополнительные модули, происхождение следует проверить."),
        new Rule("shell","Создание процессов","Обнаружено обращение к Runtime.exec или ProcessBuilder."),
        new Rule("network","Сетевой API","Есть потенциальные вызовы HTTP. Данные, адрес и фактическая отправка не определены."),
        new Rule("android-id","Android ID","Обращение к Settings.Secure.getString, ключ может быть не ANDROID_ID.")
    };
    static final String[][] SDK_PREFIXES={
        {"Lcom/google/android/gms/ads/","Google Mobile Ads"},
        {"Lcom/applovin/","AppLovin"},
        {"Lcom/unity3d/ads/","Unity Ads"},
        {"Lcom/ironsource/","ironSource"},
        {"Lcom/facebook/ads/","Meta Audience Network"},
        {"Lcom/google/firebase/analytics/","Firebase Analytics"},
        {"Lcom/google/android/gms/measurement/","Google Analytics / Measurement"},
        {"Lcom/facebook/appevents/","Meta App Events"},
        {"Lcom/appsflyer/","AppsFlyer"},
        {"Lcom/adjust/sdk/","Adjust"},
        {"Lcom/singular/sdk/","Singular"},
        {"Lcom/branch/","Branch"},
        {"Lcom/google/firebase/crashlytics/","Firebase Crashlytics"},
        {"Lio/sentry/","Sentry"},
        {"Lcom/onesignal/","OneSignal"}
    };
    private PrivacyCodeAnalyzer(){}

    public static String categoryForReference(String ref){
        if(ref==null)return "";
        if(ref.contains("AdvertisingIdClient;")||ref.contains("AdvertisingId;"))return "ad-id";
        if(ref.contains("Landroid/provider/Settings$Secure;->getString("))return "android-id";
        if(ref.contains("Landroid/telephony/TelephonyManager;->getImei(")||
           ref.contains("Landroid/telephony/TelephonyManager;->getDeviceId(")||
           ref.contains("Landroid/telephony/TelephonyManager;->getSubscriberId("))return "device-id";
        if(ref.contains("Landroid/location/LocationManager;->getLastKnownLocation(")||
           ref.contains("Landroid/location/LocationManager;->requestLocationUpdates(")||
           ref.contains("LFusedLocationProviderClient;->getLastLocation("))return "location";
        if(ref.contains("Landroid/provider/ContactsContract$")||
           ref.contains("Landroid/provider/CallLog$Calls;"))return "contacts";
        if(ref.contains("Landroid/telephony/SmsManager;->send")||
           ref.contains("Landroid/provider/Telephony$Sms;"))return "sms";
        if(ref.contains("Landroid/media/AudioRecord;")||
           ref.contains("Landroid/media/MediaRecorder;->start("))return "microphone";
        if(ref.contains("Landroid/hardware/Camera;->open(")||
           ref.contains("Landroid/hardware/camera2/CameraManager;->openCamera("))return "camera";
        if(ref.contains("Landroid/webkit/WebView;->addJavascriptInterface(")||
           ref.contains("Landroid/webkit/WebView;->evaluateJavascript("))return "webview";
        if(ref.contains("Ldalvik/system/DexClassLoader;")||
           ref.contains("Ldalvik/system/InMemoryDexClassLoader;"))return "dynamic-code";
        if(ref.contains("Ljava/lang/Runtime;->exec(")||
           ref.contains("Ljava/lang/ProcessBuilder;->start("))return "shell";
        if(ref.contains("Lokhttp3/Call;->execute(")||
           ref.contains("Lokhttp3/Call;->enqueue(")||
           ref.contains("Ljava/net/HttpURLConnection;->connect("))return "network";
        return "";
    }
    public static Rule rule(String id){
        for(Rule r:RULES)if(r.id.equals(id))return r;
        return null;
    }
    public static Report inspect(String[] paths)throws IOException{
        if(paths==null)throw new IOException("Отсутствует APK");
        Report r=new Report();
        outer:
        for(int p=0;p<Math.min(16,paths.length);p++){
            String path=paths[p];
            if(path==null||path.isEmpty())continue;
            try(ZipFile zip=new ZipFile(path)){
                Enumeration<? extends ZipEntry> entries=zip.entries();
                while(entries.hasMoreElements()){
                    ZipEntry entry=entries.nextElement();
                    if(!entry.getName().matches("classes(?:[0-9]+)?\\.dex"))continue;
                    if(Thread.currentThread().isInterrupted())throw new IOException("Отменено");
                    try {
                        DexBackedDexFile dex=DexCodeReader.load(zip,entry);
                        r.dexFiles++;
                        for(ClassDef cls:dex.getClasses()){
                            r.classes++;
                            for(String[] sdk:SDK_PREFIXES)
                                if(cls.getType().startsWith(sdk[0])){
                                    Integer count=r.sdkPackages.get(sdk[1]);
                                    r.sdkPackages.put(sdk[1],count==null?1:count+1);
                                }
                            for(Method method:cls.getMethods()){
                                if(++r.methods>90000){r.limited=true;break outer;}
                                MethodImplementation body=method.getImplementation();
                                if(body==null)continue;
                                String methodName=cls.getType()+"->"+method.getName()+"(...)";
                                for(Instruction ins:body.getInstructions()){
                                    if(++r.inspectedInstructions>650000){r.limited=true;break outer;}
                                    if(!(ins instanceof ReferenceInstruction))continue;
                                    String reference;
                                    try{reference=ReferenceUtil.getReferenceString(
                                        ((ReferenceInstruction)ins).getReference());}
                                    catch(RuntimeException ignored){continue;}
                                    String category=categoryForReference(reference);
                                    if(category.isEmpty())continue;
                                    Integer old=r.ruleCounts.get(category);
                                    r.ruleCounts.put(category,old==null?1:old+1);
                                    if(r.evidence.size()<180)
                                        r.evidence.add(new Evidence(category,methodName,shorten(reference,240)));
                                    if((r.inspectedInstructions&0x3fff)==0&&Thread.currentThread().isInterrupted())
                                        throw new IOException("Отменено");
                                }
                            }
                        }
                    }catch(IOException ex){
                        throw ex;
                    }catch(RuntimeException ex){
                        if(r.warnings.size()<16)
                            r.warnings.add(entry.getName()+": "+ex.getClass().getSimpleName());
                    }
                }
            }catch(IOException ex){throw ex;}
        }
        if(r.evidence.size()>=180||r.limited)r.warnings.add("Отчёт ограничен: не все вызовы показаны.");
        r.warnings.add("Статические ссылки НЕ доказывают исполнение, передачу данных или вредоносность.");
        r.warnings.add("SDK иногда встраиваются без исходных имён; отсутствие совпадений не исключает трекинг.");
        return r;
    }
    private static String shorten(String s,int max){return s.length()>max?s.substring(0,max)+"…":s;}
    public static String printable(Report r){
        StringBuilder sb=new StringBuilder("ASTER · анализ API вызовов\n").append(r.summary()).append("\n\n");
        sb.append("БИБЛИОТЕКИ / SDK (обнаружены классы, версия неизвестна)\n");
        for(Map.Entry<String,Integer> x:r.sdkPackages.entrySet())
            sb.append("· ").append(x.getKey()).append(" — ").append(x.getValue()).append(" классов\n");
        sb.append("\nВЫЗОВЫ, ТРЕБУЮЩИЕ ПРОВЕРКИ\n");
        for(Map.Entry<String,Integer> x:r.ruleCounts.entrySet()){
            Rule rule=rule(x.getKey());
            if(rule!=null)sb.append("· ").append(rule.label).append(" — ").append(x.getValue()).append(" ссылок\n");
        }
        sb.append("\nКОДОВЫЕ ССЫЛКИ (НЕ runtime-трасса)\n");
        for(Evidence e:r.evidence){
            Rule rule=rule(e.rule);
            sb.append(rule==null?e.rule:rule.label).append("\n")
                .append("  ").append(e.method).append("\n  → ").append(e.reference).append("\n");
        }
        sb.append("\nОГРАНИЧЕНИЯ\n");
        for(String w:r.warnings)sb.append("· ").append(w).append("\n");
        return sb.toString();
    }
}
