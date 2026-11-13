package dev.aster.guard;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.FileInputStream;
import java.security.MessageDigest;
import android.graphics.Typeface;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Built-in privacy/code lab. It does NOT host a fake Android VM or execute
 * potentially malicious APKs in the phone's main OS. Activity journal is ASTER
 * actions only, and all DEX call references are static evidence.
 */
public final class PrivacyLabActivity extends Activity {
    private static final int BG=0xff0f1523,SURFACE=0xff1a2534,TEXT=0xffedf6fa,
        MUTED=0xffa4b8c8,MINT=0xff8cecd4,AMBER=0xffffca82;
    private static final String[] OPS={
        "FINE_LOCATION","COARSE_LOCATION","READ_CONTACTS","READ_CALL_LOG",
        "READ_SMS","CAMERA","RECORD_AUDIO"
    };
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final List<String> journal=new ArrayList<>();
    private String pkg="",label="",archivePath="",status="Ожидание запуска анализа";
    private PrivacyCodeAnalyzer.Report report;
    private LinearLayout root,content;
    private boolean busy;
    private int dp(int v){return Math.round(v*getResources().getDisplayMetrics().density);}
    @Override public void onCreate(Bundle saved){
        super.onCreate(saved);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        Intent intent=getIntent();
        pkg=intent.getStringExtra("packageName");
        if(pkg==null)pkg="";
        archivePath=intent.getStringExtra("archivePath");
        if(archivePath==null)archivePath="";
        label=intent.getStringExtra("label");
        if(label==null||label.isEmpty())label=pkg.isEmpty()?"APK":pkg;
        if(!archivePath.isEmpty()&&!checkCachePath(archivePath)){finish();return;}
        if(pkg.isEmpty()&&archivePath.isEmpty()){finish();return;}
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);root.setPadding(dp(12),dp(8),dp(12),dp(4));
        setContentView(root);
        LinearLayout nav=new LinearLayout(this);nav.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(nav);
        nav.addView(button("‹ Назад",this::finish));
        TextView heading=text("ASTER · лаборатория кода",19,MINT);
        heading.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        nav.addView(heading);
        ScrollView scroll=new ScrollView(this);
        content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(5),dp(6),dp(5),dp(25));
        scroll.addView(content);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        event("Лаборатория открыта для "+label);
        render();
    }
    private boolean checkCachePath(String path){
        try{
            File file=new File(path).getCanonicalFile();
            File cache=getCacheDir().getCanonicalFile();
            return file.isFile()&&file.getParentFile().equals(cache)&&
                file.getName().endsWith(".apk")&&file.length()<=96L*1024*1024;
        }catch(Exception ignored){return false;}
    }
    private TextView text(String s,int size,int color){
        TextView t=new TextView(this);t.setText(s);t.setTextSize(size);
        t.setTextColor(color);t.setPadding(dp(7),dp(8),dp(7),dp(8));
        return t;
    }
    private Button button(String s,Runnable action){
        Button b=new Button(this);b.setText(s);b.setAllCaps(false);b.setTextSize(12);
        b.setOnClickListener(v->action.run());
        return b;
    }
    private void line(String s,int size,int color){content.addView(text(s,size,color));}
    private void event(String message){
        String time=DateFormat.getTimeInstance(DateFormat.MEDIUM).format(new Date());
        synchronized(journal){
            if(journal.size()>=220)journal.remove(0);
            journal.add(time+" · "+message);
        }
    }
    private void render(){
        if(isFinishing()||isDestroyed())return;
        content.removeAllViews();
        line(label,20,TEXT);
        line(archivePath.isEmpty()?"Установленное приложение: "+pkg:
            "Выбранный APK · анализ без установки и запуска",12,MUTED);
        line("Анализ DEX: ссылки на рекламные SDK, API идентификаторов, геолокацию, SMS, камеру, микрофон и сетевые вызовы. Ссылки НЕ доказывают, что приложение их выполняло.",13,MUTED);
        if(busy){line("Чтение DEX в фоновом потоке…",14,MINT);}
        else content.addView(button(report==null?"Проанализировать код":"Повторить анализ DEX",this::analyze));
        if(report!=null)showResults();
        if(!archivePath.isEmpty())content.addView(button("Открыть DEX / Smali просмотрщик",this::openDex));
        else{
            content.addView(button("Открыть DEX / Smali просмотрщик",this::openDex));
            content.addView(button("Ограничить доступы приложения (Shizuku)",this::showAppOps));
        }
        if(report!=null)content.addView(button("Скопировать отчёт и план приватности",this::copyReport));
        content.addView(button("Поделиться журналом действий ASTER",this::shareJournal));
        section("Динамический анализ · отдельная Android-песочница");
        line("Теперь можно продолжить исследование этого же APK в ASTER Sandbox Analyzer: "+
            "снимок гостевой системы до установки → запуск под наблюдением → "+
            "сравнение изменений → единый отчёт JSON/HTML → восстановление. "+
            "Результаты статического DEX-анализа будут включены в отчёт при совпадении SHA-256.",13,TEXT);
        if(!archivePath.isEmpty()){
            content.addView(button("Продолжить: анализ поведения APK в Android Lab",this::openDynamicLab));
            line("Выбранный APK будет передан только на ВАШ сопряжённый лабораторный компьютер "+
                "после явного подтверждения. Никакой запуск на основном телефоне не выполняется.",12,AMBER);
        }else{
            content.addView(button("Открыть Android Lab (выбор APK)",this::openDynamicLab));
            line("Для установленного приложения выберите его исходный APK через системный "+
                "проводник в Android Lab. Эта страница сама приложение не запускает.",12,MUTED);
        }
        line("Полноценный Android 7+ с root работает на отдельном AOSP-эмуляторе под "+
            "управлением ASTER. На основном телефоне пока доступен только статический анализ. "+
            "Shizuku не создаёт независимую виртуальную ОС и не обеспечивает её изоляцию.",12,AMBER);
        section("Журнал ASTER");
        line("Ниже журнал действий интерфейса и статического анализа, а не системный "+
            "журнал гостевого приложения. Системный отчёт создаётся в Android Lab.",12,MUTED);
        synchronized(journal){
            for(int i=Math.max(0,journal.size()-16);i<journal.size();i++)
                line("• "+journal.get(i),12,MUTED);
        }
    }
    private void section(String heading){
        TextView title=text(heading,16,MINT);
        title.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        content.addView(title);
    }
    private void showResults(){
        PrivacyCodeAnalyzer.Report r=report;
        section("Результат: "+r.summary());
        if(r.sdkPackages.isEmpty()&&r.ruleCounts.isEmpty())
            line("Совпадений не найдено. Это НЕ означает, что реклама или трекинг отсутствуют.",13,MUTED);
        if(!r.sdkPackages.isEmpty()){
            section("Распознанные SDK (не доказанные сетевые запросы)");
            for(Map.Entry<String,Integer> x:r.sdkPackages.entrySet())
                line("• "+x.getKey()+" · классов "+x.getValue(),13,TEXT);
        }
        if(!r.ruleCounts.isEmpty()){
            section("Потенциальные вызовы API");
            for(Map.Entry<String,Integer> x:r.ruleCounts.entrySet()){
                PrivacyCodeAnalyzer.Rule rule=PrivacyCodeAnalyzer.rule(x.getKey());
                if(rule!=null)line("• "+rule.label+": "+x.getValue()+
                    " ссылок\n"+rule.details,13,TEXT);
            }
        }
        section("Контекст кода (первые 45 свидетельств)");
        int cap=Math.min(45,r.evidence.size());
        for(int i=0;i<cap;i++){
            PrivacyCodeAnalyzer.Evidence e=r.evidence.get(i);
            PrivacyCodeAnalyzer.Rule rule=PrivacyCodeAnalyzer.rule(e.rule);
            line("• "+(rule==null?e.rule:rule.label)+
                "\n"+e.method+"\n→ "+e.reference,12,MUTED);
        }
        if(!r.warnings.isEmpty()){
            section("Ограничения");
            for(String warning:r.warnings)line("• "+warning,12,AMBER);
        }
        section("План уменьшения слежки");
        line("1. Проверьте, реально ли используется найденный API, через легитимные настройки разрешений, AppOps и сетевые метаданные.\n"+
             "2. Для установленного приложения можно изменить выбранные AppOps через Shizuku — это не модификация APK.\n"+
             "3. Удаление рекламных SDK из чужого APK требует правильной переработки кода, сборки и новой подписи; "+
             "универсальное удаление вызовов может сломать приложение и нарушить его подпись.\n"+
             "4. ASTER не выполнял никаких изменений APK и не обходил лицензию/платежи.",13,MUTED);
    }
    private void analyze(){
        if(busy)return;busy=true;status="Чтение DEX";event("Начата статическая проверка DEX");
        render();
        worker.execute(()->{
            try{
                String[] paths;
                if(!archivePath.isEmpty())paths=new String[]{archivePath};
                else{
                    ApplicationInfo info=getPackageManager().getApplicationInfo(pkg,0);
                    if(info.splitSourceDirs==null)paths=new String[]{info.sourceDir};
                    else{
                        paths=new String[info.splitSourceDirs.length+1];
                        paths[0]=info.sourceDir;System.arraycopy(info.splitSourceDirs,0,paths,1,info.splitSourceDirs.length);
                    }
                }
                PrivacyCodeAnalyzer.Report r=PrivacyCodeAnalyzer.inspect(paths);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    report=r;busy=false;
                    event("DEX проверены: "+r.dexFiles+" · ссылок на API: "+r.evidence.size());
                    render();
                });
            }catch(Exception e){
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    busy=false;event("Ошибка анализа: "+e.getClass().getSimpleName());
                    new AlertDialog.Builder(this).setTitle("Ошибка анализа")
                        .setMessage(e.getMessage()).setPositiveButton("Закрыть",null).show();
                    render();
                });
            }
        });
    }
    /** Carry the exact user-selected cached APK into the isolated lab workflow. */
    private void openDynamicLab(){
        if(busy)return;
        if(archivePath.isEmpty()){
            startActivity(new Intent(this,GuestLabActivity.class));
            return;
        }
        if(!checkCachePath(archivePath)){
            new AlertDialog.Builder(this).setTitle("APK недоступен")
                .setMessage("Исходный файл из кэша ASTER больше не доступен. "+
                    "Выберите APK заново через проверку файлов.")
                .setPositiveButton("Закрыть",null).show();
            return;
        }
        new AlertDialog.Builder(this).setTitle("Передать APK в гостевую лабораторию?")
            .setMessage("Продолжим исследование выбранного APK. После подключения "+
                "к вашему частному серверу потребуется отдельное подтверждение "+
                "передачи файла, а затем подтверждение запуска в root-эмуляторе. "+
                "На основном телефоне APK никогда не запустится.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Перейти к анализу",(dialog,which)->{
                busy=true;render();
                worker.execute(()->{
                    String staticJson="";
                    try{
                        File selected=new File(archivePath).getCanonicalFile();
                        if(!checkCachePath(selected.getPath()))
                            throw new java.io.IOException("APK недоступен");
                        MessageDigest digest=MessageDigest.getInstance("SHA-256");
                        try(FileInputStream input=new FileInputStream(selected)){
                            byte[] bytes=new byte[65536];int count;
                            while((count=input.read(bytes))!=-1)
                                digest.update(bytes,0,count);
                        }
                        StringBuilder hash=new StringBuilder();
                        for(byte value:digest.digest())
                            hash.append(String.format(Locale.ROOT,"%02x",value&255));
                        JSONObject evidence=new JSONObject()
                            .put("schema","aster-static-v1")
                            .put("sha256",hash.toString())
                            .put("source","on_device_dex_references_only")
                            .put("filename",label.substring(0,Math.min(label.length(),120)))
                            .put("complete",report!=null&&!report.limited)
                            .put("dex_files",report==null?0:report.dexFiles)
                            .put("classes",report==null?0:report.classes)
                            .put("methods",report==null?0:report.methods);
                        JSONObject sdk=new JSONObject(),calls=new JSONObject();
                        if(report!=null){
                            int n=0;
                            for(Map.Entry<String,Integer> e:report.sdkPackages.entrySet()){
                                if(++n>24)break;
                                sdk.put(e.getKey(),e.getValue());
                            }
                            n=0;
                            for(Map.Entry<String,Integer> e:report.ruleCounts.entrySet()){
                                if(++n>32)break;
                                calls.put(e.getKey(),e.getValue());
                            }
                        }
                        evidence.put("sdk_references",sdk).put("api_references",calls)
                            .put("warning","Static call references do NOT prove execution.");
                        staticJson=evidence.toString();
                    }catch(Exception e){
                        event("Не удалось добавить статические сведения: "+e.getClass().getSimpleName());
                    }
                    final String serialized=staticJson;
                    runOnUiThread(()->{
                        if(isFinishing()||isDestroyed())return;
                        busy=false;render();
                        Intent intent=new Intent(this,GuestLabActivity.class);
                        intent.putExtra("archivePath",archivePath);
                        intent.putExtra("label",label);
                        if(!serialized.isEmpty())intent.putExtra("staticAnalysis",serialized);
                        event("Открыт Sandbox Analyzer для этого же APK (ещё без запуска)");
                        startActivity(intent);
                    });
                });
            }).show();
    }
    private void openDex(){
        Intent intent=new Intent(this,DexExplorerActivity.class);
        intent.putExtra("packageName",pkg.isEmpty()?"unknown":pkg);
        intent.putExtra("label",label);
        if(!archivePath.isEmpty())intent.putExtra("archivePath",archivePath);
        event("Открыт просмотрщик DEX (только чтение)");
        startActivity(intent);
    }
    private void copyReport(){
        if(report==null)return;
        ClipboardManager cb=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
        if(cb!=null)cb.setPrimaryClip(ClipData.newPlainText("ASTER · audit",
            PrivacyCodeAnalyzer.printable(report)+"\nИзменения кода/подписи APK НЕ выполнялись."));
        event("Отчёт скопирован в буфер обмена");
        render();
    }
    private void showAppOps(){
        if(!ShizukuBridge.authorized()){
            new AlertDialog.Builder(this).setTitle("Shizuku недоступен")
                .setMessage("Для изменения AppOps сначала установите, запустите и разрешите Shizuku. На большинстве устройств достаточно беспроводной отладки; root не требуется.")
                .setPositiveButton("Закрыть",null).show();
            return;
        }
        new AlertDialog.Builder(this).setTitle("Выберите доступ приложения")
            .setItems(OPS,(dialog,index)->confirmOp(OPS[index]))
            .setNegativeButton("Отмена",null).show();
    }
    private void confirmOp(String op){
        new AlertDialog.Builder(this).setTitle(pkg+" · "+op)
            .setMessage("Shizuku изменит системный AppOps для конкретного приложения. "+
                "Это может нарушить его работу. «Сбросить» установит системное значение default "+
                "(не обязательно исходный пользовательский выбор). Команда не изменяет сам APK.")
            .setPositiveButton("Запретить",(d,w)->changeOp(op,true))
            .setNeutralButton("Сбросить в default",(d,w)->changeOp(op,false))
            .setNegativeButton("Отмена",null).show();
    }
    private void changeOp(String op,boolean block){
        event("Пользователь запросил AppOps "+op+" → "+(block?"ignore":"default"));
        render();
        worker.execute(()->{
            try{
                String result=ShizukuBridge.setPrivacyOp(getApplicationContext(),pkg,op,block);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    event("Ответ Shizuku: "+result.replace('\n',' ').substring(0,Math.min(result.length(),100)));
                    new AlertDialog.Builder(this).setTitle("Результат Shizuku")
                        .setMessage(result).setPositiveButton("Закрыть",null).show();
                    render();
                });
            }catch(Exception ex){
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    event("Ошибка AppOps: "+ex.getClass().getSimpleName());
                    new AlertDialog.Builder(this).setTitle("Shizuku: отказ")
                        .setMessage(ex.toString()).setPositiveButton("Закрыть",null).show();render();
                });
            }
        });
    }
    private void shareJournal(){
        StringBuilder sb=new StringBuilder("ASTER · ЖУРНАЛ СТАТИЧЕСКОЙ ЛАБОРАТОРИИ\n");
        synchronized(journal){for(String row:journal)sb.append(row).append('\n');}
        sb.append("\nНЕ является журналом действий гостевой VM или запущенного APK.");
        Intent share=new Intent(Intent.ACTION_SEND);
        share.setType("text/plain");share.putExtra(Intent.EXTRA_TEXT,sb.toString());
        event("Журнал подготовлен для отправки по выбору пользователя");
        startActivity(Intent.createChooser(share,"Журнал ASTER"));
    }
    @Override protected void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
