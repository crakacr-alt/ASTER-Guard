package dev.aster.guard;

import android.app.Activity;
import java.io.InputStream;
import android.app.NotificationManager;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.content.ContentResolver;
import android.app.usage.UsageStatsManager;
import rikka.shizuku.Shizuku;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Native, dependency-free dark UI. Nothing executes in a background service.
 * The worker is used only after a direct user action.
 */
public final class MainActivity extends Activity {
    private static final int BG=0xFF090D15, SURFACE=0xFF131B28, SURFACE2=0xFF192333,
            TEXT=0xFFF3F7FC, MUTED=0xFF9DAAC0, MINT=0xFF8CF1CE,
            BLUE=0xFF9EAFFF, AMBER=0xFFFFC87F, RED=0xFFFF849A,
            BORDER=0xFF263347;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean cancelled=new AtomicBoolean(false);
    private final List<AppRecord> apps=new ArrayList<>();
    private List<NetworkReader.Usage> networkUsage=new ArrayList<>();
    private LinearLayout root,body,appList;
    private int tab=0,scanDone=0,scanTotal=0,filter=0;
    private boolean scanning=false,loadingNetwork=false;
    private boolean loadingForeground=false;
    private UpdateChecker.Update newRelease;
    private String updateError="";
    private final List<DeviceHealth.AppActivity> foregroundApps=new ArrayList<>();
    private static final int PCAP_PICKER=2082;
    private static final int LIVE_START=2083, LIVE_STOP=2084;
    private LiveCaptureSession liveSession;
    private boolean liveAuthorized=false;
    private String liveWarning="";
    private final Shizuku.OnRequestPermissionResultListener shizukuListener=(code,grant)->{
        if(code==ShizukuBridge.REQUEST_CODE && !isFinishing()){
            Toast.makeText(this,grant==PackageManager.PERMISSION_GRANTED?
                "Shizuku разрешён":"Shizuku не разрешён",Toast.LENGTH_SHORT).show();
            render();
        }
    };
    private String query="",networkError="";
    private long lastScan=0;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        if (Build.VERSION.SDK_INT>=29) getWindow().setNavigationBarContrastEnforced(false);
        lastScan=0; // Results are not persisted: never present a stale clean scan after restart.
        root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        if(Build.VERSION.SDK_INT>=35) {
            root.setOnApplyWindowInsetsListener((v,insets)->{
                android.graphics.Insets sys=insets.getInsets(WindowInsets.Type.systemBars());
                v.setPadding(0,sys.top,0,sys.bottom);
                return insets;
            });
        }
        setContentView(root);
        GameModeSession.restoreIfExpired(this);
        render();
        try{Shizuku.addRequestPermissionResultListener(shizukuListener);}catch(Throwable ignored){}
        // Exactly one check per application launch, never a scheduled/background poll.
        worker.execute(()->{
            try{
                UpdateChecker.Update release=UpdateChecker.check(getApplicationContext());
                runOnUiThread(()->{if(!isFinishing()&&!isDestroyed()){newRelease=release;render();}});
            }catch(Exception e){
                updateError=e.getClass().getSimpleName();
            }
        });
    }

    @Override protected void onDestroy() {
        cancelled.set(true);
        try{Shizuku.removeRequestPermissionResultListener(shizukuListener);}catch(Throwable ignored){}
        if(liveSession!=null)liveSession.close(); // PCAPdroid remains independently controlled by user.
        worker.shutdownNow();
        super.onDestroy();
    }

    private int dp(float value) { return (int)(value*getResources().getDisplayMetrics().density+0.5f); }
    private GradientDrawable shape(int color,int radius) {
        GradientDrawable d=new GradientDrawable();
        d.setColor(color); d.setCornerRadius(dp(radius));
        return d;
    }
    private GradientDrawable outline(int color,int radius) {
        GradientDrawable d=shape(color,radius);
        d.setStroke(dp(1),BORDER);
        return d;
    }
    private RippleDrawable ripple(int bg,int r) {
        return new RippleDrawable(ColorStateList.valueOf(0x33FFFFFF),shape(bg,r),null);
    }
    private TextView text(String s,int size,int color,boolean bold) {
        TextView t=new TextView(this);
        t.setText(s);
        t.setTextSize(size);
        t.setTextColor(color);
        t.setIncludeFontPadding(true);
        if(bold) t.setTypeface(Typeface.create("sans-serif",Typeface.BOLD));
        else t.setTypeface(Typeface.create("sans-serif",Typeface.NORMAL));
        return t;
    }
    private TextView spaced(String s,int size,int color,boolean bold) {
        TextView t=text(s,size,color,bold); t.setLetterSpacing(.10f); return t;
    }
    private LinearLayout column() {
        LinearLayout l=new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l;
    }
    private LinearLayout row() {
        LinearLayout l=new LinearLayout(this); l.setOrientation(LinearLayout.HORIZONTAL);
        l.setGravity(Gravity.CENTER_VERTICAL); return l;
    }
    private LinearLayout card() {
        LinearLayout l=column();
        l.setPadding(dp(18),dp(18),dp(18),dp(18));
        l.setBackground(outline(SURFACE,24));
        return l;
    }
    private void gap(LinearLayout parent,int height) {
        View v=new View(this); parent.addView(v,new LinearLayout.LayoutParams(1,dp(height)));
    }
    private void line(LinearLayout parent) {
        View v=new View(this); v.setBackgroundColor(BORDER);
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,dp(1));
        p.topMargin=dp(14);p.bottomMargin=dp(14);parent.addView(v,p);
    }
    private LinearLayout.LayoutParams weight() { return new LinearLayout.LayoutParams(0,-2,1f); }
    private LinearLayout.LayoutParams fill(int bottom) {
        LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);
        p.bottomMargin=dp(bottom); return p;
    }
    private TextView button(String label,boolean primary,View.OnClickListener action) {
        TextView t=text(label,15,primary?BG:TEXT,true);
        t.setGravity(Gravity.CENTER);
        t.setPadding(dp(18),dp(15),dp(18),dp(15));
        t.setBackground(ripple(primary?MINT:SURFACE2,16));
        t.setOnClickListener(action);
        t.setClickable(true); t.setFocusable(true);
        return t;
    }
    private TextView pill(String label,int fg,int bg) {
        TextView t=text(label,11,fg,true);
        t.setPadding(dp(11),dp(6),dp(11),dp(6));
        t.setBackground(shape(bg,50)); return t;
    }
    private int riskColor(int score) {
        if(score>=70) return RED;
        if(score>=35) return AMBER;
        if(score>=15) return BLUE;
        return MINT;
    }
    private String formatSize(long bytes) {
        if(bytes<0) return "—";
        if(bytes<1024) return bytes+" Б";
        double kb=bytes/1024.0;
        if(kb<1024) return String.format(Locale.getDefault(),"%.1f КБ",kb);
        double mb=kb/1024.0;
        if(mb<1024) return String.format(Locale.getDefault(),"%.1f МБ",mb);
        return String.format(Locale.getDefault(),"%.2f ГБ",mb/1024.0);
    }

    private void render() {
        if(isFinishing() || isDestroyed()) return;
        root.removeAllViews();
        header();
        ScrollView scroll=new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setVerticalScrollBarEnabled(false);
        body=column();
        body.setPadding(dp(20),dp(12),dp(20),dp(24));
        scroll.addView(body);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        if(tab==0) showDashboard();
        else if(tab==1) showApps();
        else if(tab==2) showNetwork();
        else if(tab==3) showSystem();
        else showSettings();
        navigation();
    }

    private void header() {
        LinearLayout top=row();
        top.setPadding(dp(21),dp(14),dp(21),dp(12));
        TextView symbol=text("✦",29,MINT,true);
        top.addView(symbol);
        LinearLayout brand=column();
        LinearLayout.LayoutParams bp=new LinearLayout.LayoutParams(0,-2,1);
        bp.leftMargin=dp(12);
        brand.addView(spaced("ASTER",18,TEXT,true));
        brand.addView(spaced("G U A R D",9,MINT,true));
        top.addView(brand,bp);
        TextView local=pill("●  LOCAL",MINT,0xFF183C36);
        top.addView(local);
        root.addView(top);
    }

    private void sectionLabel(LinearLayout parent,String label) {
        TextView v=spaced(label,11,MUTED,true);
        parent.addView(v,fill(12));
    }

    private void sectionTitle(LinearLayout parent,String title,String subtitle) {
        parent.addView(text(title,28,TEXT,true),fill(4));
        parent.addView(text(subtitle,13,MUTED,false),fill(22));
    }

    private void showDashboard() {
        sectionTitle(body,"Обзор защиты","Проверка запускается только по вашему запросу");
        if(newRelease!=null) {
            LinearLayout update=card();
            update.addView(text("Доступна новая версия: "+newRelease.version,16,MINT,true),fill(10));
            update.addView(text("GitHub Releases · скачивание по вашему выбору",12,MUTED,false),fill(12));
            update.addView(button("Открыть обновление",true,v->openExternal(newRelease.url)));
            body.addView(update,fill(16));
        }
        LinearLayout hero=column();
        hero.setPadding(dp(23),dp(22),dp(23),dp(22));
        GradientDrawable grad=new GradientDrawable(GradientDrawable.Orientation.TL_BR,
                new int[]{0xFF23394A,0xFF172235,0xFF141A2A});
        grad.setCornerRadius(dp(28));hero.setBackground(grad);
        hero.addView(spaced("ЛОКАЛЬНЫЙ АНАЛИЗ",11,MINT,true));
        gap(hero,12);
        String title=scanning?"Идёт проверка":lastScan==0?"Готов к сканированию":"Последняя проверка";
        hero.addView(text(title,23,TEXT,true));
        gap(hero,5);
        String description=scanning?"Анализируем доступные сведения об APK"
                :lastScan==0?"Никакой отправки данных на сервер"
                :"Результаты относятся к моменту последнего сканирования";
        hero.addView(text(description,13,MUTED,false));
        gap(hero,17);
        Ring ring=new Ring();
        int flagged=0,high=0;
        for(AppRecord r:apps) { if(r.score>=15) flagged++; if(r.score>=70) high++; }
        ring.setMode(scanning,scanning&&scanTotal>0 ? (float)scanDone/scanTotal : 1f,
                scanning?scanDone:(lastScan==0?0:flagged));
        LinearLayout cent=row();cent.setGravity(Gravity.CENTER);
        cent.addView(ring,new LinearLayout.LayoutParams(dp(176),dp(176)));
        hero.addView(cent);
        gap(hero,12);
        TextView caption=text(scanning ? (scanDone+" из "+scanTotal+" приложений")
                :lastScan==0?"Нажмите кнопку, чтобы начать"
                :flagged==0?"Эвристика не отметила подозрений":"Приложений с признаками риска: "+flagged,
                13,TEXT,true);
        caption.setGravity(Gravity.CENTER);
        hero.addView(caption);
        gap(hero,17);
        hero.addView(button(scanning?"Остановить проверку":"Начать проверку",true,v->{
            if(scanning) cancelled.set(true);
            else startScan();
        }));
        body.addView(hero,fill(18));
        LinearLayout fileCard=card();
        fileCard.addView(text("Проверка файла из памяти",18,TEXT,true),fill(8));
        fileCard.addView(text("APK без установки, EXE, PDF, Word, PowerPoint, PNG и любые другие файлы. Проверяем формат, SHA-256, скрипты и вложения локально.",13,MUTED,false),fill(12));
        fileCard.addView(button("Выбрать и проверить файл",true,v->openFileScanner()));
        fileCard.addView(button("Лаборатория · Android-гость и трассировка",false,
            v->startActivity(new Intent(this,GuestLabActivity.class))),fill(10));
        body.addView(fileCard,fill(18));

        LinearLayout metrics=row();
        metrics.addView(metric("ПРИЛОЖЕНИЯ",lastScan==0?"—":String.valueOf(apps.size()),MINT),weight());
        gapHorizontal(metrics,10);
        metrics.addView(metric("ВЫСОКИЙ РИСК",lastScan==0?"—":String.valueOf(high),high>0?RED:MINT),weight());
        body.addView(metrics,fill(24));

        sectionLabel(body,"ОТЧЁТ");
        LinearLayout report=card();
        if(lastScan==0) {
            report.addView(text("Проверок пока не было",17,TEXT,true));
            gap(report,6);
            report.addView(text("Мы проверим разрешения, подписи, компоненты и настройки приложений.",13,MUTED,false));
        } else {
            report.addView(text(DateFormat.getDateTimeInstance(DateFormat.MEDIUM,DateFormat.SHORT)
                    .format(new Date(lastScan)),14,TEXT,true));
            gap(report,8);
            report.addView(text("Результат — оценка признаков риска, а не подтверждение наличия вируса.",13,MUTED,false));
            gap(report,14);
            report.addView(button("Поделиться кратким отчётом",false,v->shareReport()));
        }
        body.addView(report,fill(24));

        if(lastScan!=0) {
            sectionLabel(body,"ТРЕБУЮТ ВНИМАНИЯ");
            int shown=0;
            for(AppRecord r:apps) {
                if(r.score<15) continue;
                body.addView(appItem(r),fill(9));
                if(++shown==5) break;
            }
            if(shown==0) {
                LinearLayout clean=card();
                clean.addView(text("По заданным правилам риски не выделены",15,MINT,true));
                gap(clean,5);
                clean.addView(text("Это не исключает скрытых или неизвестных угроз.",12,MUTED,false));
                body.addView(clean);
            } else {
                body.addView(button("Посмотреть все приложения",false,v->{tab=1;render();}));
            }
        }
    }

    private void gapHorizontal(LinearLayout parent,int width) {
        View v=new View(this);parent.addView(v,new LinearLayout.LayoutParams(dp(width),1));
    }
    private LinearLayout metric(String title,String value,int accent) {
        LinearLayout c=column();c.setPadding(dp(16),dp(15),dp(14),dp(14));
        c.setBackground(outline(SURFACE,20));
        c.addView(text(title,10,MUTED,true));
        gap(c,9);
        c.addView(text(value,25,accent,true));
        return c;
    }

    private void openFileScanner(){
        startActivity(new Intent(this,FileScanActivity.class));
    }

    private void showApps() {
        sectionTitle(body,"Приложения","Подробности, разрешения и цифровые подписи");
        body.addView(button("Проверить неустановленный APK или другой файл",true,v->openFileScanner()),fill(18));
        if(lastScan==0) {
            LinearLayout c=card();
            c.addView(text("Список появится после первой проверки",16,TEXT,true));
            gap(c,12);
            c.addView(button("Сканировать устройство",true,v->{tab=0;render();startScan();}));
            body.addView(c);return;
        }
        EditText search=new EditText(this);
        search.setSingleLine(true);
        search.setTextColor(TEXT);
        search.setHintTextColor(MUTED);
        search.setTextSize(14);
        search.setHint("Поиск по названию или пакету");
        search.setPadding(dp(16),dp(12),dp(16),dp(12));
        search.setBackground(outline(SURFACE,18));
        search.setText(query);
        search.setSelection(search.length());
        body.addView(search,fill(14));
        LinearLayout tabs=row();
        TextView all=button("Все · "+apps.size(),filter==0,v->{filter=0;render();});
        TextView flagged=button("С подозрениями",filter==1,v->{filter=1;render();});
        tabs.addView(all,weight());gapHorizontal(tabs,10);tabs.addView(flagged,weight());
        body.addView(tabs,fill(18));
        appList=column();
        body.addView(appList);
        refillApps();
        search.addTextChangedListener(new TextWatcher(){
            @Override public void beforeTextChanged(CharSequence s,int start,int count,int after){}
            @Override public void onTextChanged(CharSequence s,int start,int before,int count){
                query=s.toString();refillApps();
            }
            @Override public void afterTextChanged(Editable e){}
        });
    }

    private void refillApps() {
        if(appList==null || tab!=1)return;
        appList.removeAllViews();
        int count=0;
        String q=query.toLowerCase(Locale.ROOT).trim();
        for(AppRecord r:apps) {
            if(filter==1 && r.score<15) continue;
            if(!r.label.toLowerCase(Locale.ROOT).contains(q)
                && !r.packageName.toLowerCase(Locale.ROOT).contains(q)) continue;
            appList.addView(appItem(r),fill(9));
            count++;
        }
        if(count==0) appList.addView(text("По заданному фильтру ничего не найдено",14,MUTED,false));
    }

    private LinearLayout appItem(AppRecord r) {
        LinearLayout line=row();
        line.setPadding(dp(15),dp(15),dp(12),dp(15));
        line.setBackground(ripple(SURFACE,19));
        TextView icon=text(r.label.length()>0?r.label.substring(0,1).toUpperCase(Locale.ROOT):"?",19,TEXT,true);
        icon.setGravity(Gravity.CENTER);
        icon.setBackground(shape(SURFACE2,13));
        line.addView(icon,new LinearLayout.LayoutParams(dp(42),dp(42)));
        LinearLayout labels=column();
        LinearLayout.LayoutParams lp=new LinearLayout.LayoutParams(0,-2,1);
        lp.leftMargin=dp(13);
        TextView name=text(r.label,14,TEXT,true);
        name.setMaxLines(1);name.setEllipsize(android.text.TextUtils.TruncateAt.END);
        labels.addView(name);
        TextView pkg=text(r.packageName,11,MUTED,false);
        pkg.setMaxLines(1);pkg.setEllipsize(android.text.TextUtils.TruncateAt.MIDDLE);
        labels.addView(pkg);
        line.addView(labels,lp);
        line.addView(pill(String.valueOf(r.score),riskColor(r.score),SURFACE2));
        line.setOnClickListener(v->openApp(r));
        line.setClickable(true);
        return line;
    }

    private void detailRow(LinearLayout l,String label,String val) {
        l.addView(spaced(label.toUpperCase(Locale.ROOT),10,MUTED,true),fill(4));
        TextView v=text(val,13,TEXT,false);
        v.setTextIsSelectable(true);
        l.addView(v,fill(12));
    }

    private void openApp(AppRecord r) {
        LinearLayout box=column();
        box.setPadding(dp(20),dp(20),dp(20),dp(10));
        box.setBackgroundColor(SURFACE);
        box.addView(text(r.label,23,TEXT,true),fill(6));
        box.addView(text(r.packageName,12,MUTED,false),fill(12));
        box.addView(pill(r.riskLabel()+" · "+r.score+"/100",riskColor(r.score),SURFACE2),fill(17));
        sectionLabel(box,"ОБЪЯСНЕНИЕ");
        if(r.reasons.isEmpty()) {
            box.addView(text("Текущая эвристика не выявила признаков повышенного риска. Отсутствие признаков не гарантирует безопасность.",13,MUTED,false),fill(14));
        } else {
            for(String reason:r.reasons) box.addView(text("• "+reason,13,TEXT,false),fill(9));
            gap(box,7);
        }
        sectionLabel(box,"МЕТАДАННЫЕ");
        detailRow(box,"Установщик",r.installer);
        detailRow(box,"Версия / target SDK",r.version+" / "+r.targetSdk);
        detailRow(box,"Размер базового APK",formatSize(r.apkSize));
        detailRow(box,"SHA-256 сертификата",r.signerSha256.isEmpty()?"Недоступно":r.signerSha256);
        if(r.installedAt>0)detailRow(box,"Установлено",DateFormat.getDateInstance().format(new Date(r.installedAt)));
        if(r.updatedAt>0)detailRow(box,"Обновлено",DateFormat.getDateInstance().format(new Date(r.updatedAt)));
        if(!r.observations.isEmpty()) {
            sectionLabel(box,"НАБЛЮДЕНИЯ");
            for(String note:r.observations)box.addView(text("• "+note,13,MUTED,false),fill(8));
            gap(box,7);
        }
        sectionLabel(box,"РАЗРЕШЕНИЯ · "+r.requestedPermissions.size());
        if(r.requestedPermissions.isEmpty()) {
            box.addView(text("Не заявлены или недоступны",13,MUTED,false),fill(16));
        } else {
            for(String perm:r.requestedPermissions) {
                boolean granted=r.grantedPermissions.contains(perm);
                TextView tv=text((granted?"● ":"○ ")+perm.replace("android.permission.",""),12,granted?TEXT:MUTED,false);
                box.addView(tv,fill(6));
            }
            box.addView(text("● предоставлено   ○ не предоставлено / не применимо",11,MUTED,false),fill(20));
        }
        box.addView(button("Лаборатория кода, трекеров и приватности",true,v->openPrivacyLab(r)),fill(10));
        box.addView(button("Открыть код DEX / Smali · классы и методы",false,v->openDexExplorer(r)),fill(10));
        box.addView(button("Аудит APK, разрешений и библиотек",false,v->reverseEngineer(r)),fill(10));
        box.addView(button("Shizuku · инструменты приложения",false,v->openShizukuActions(r)),fill(10));
        box.addView(button("Глубокий анализ APK + SHA-256",false,v->deepAnalyze(r)),fill(10));
        box.addView(button("Системная информация о приложении",false,v->{
            Intent i=new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:"+r.packageName));
            startActivity(i);
        }));
        ScrollView s=new ScrollView(this);s.addView(box);
        AlertDialog d=new AlertDialog.Builder(this).setView(s).setPositiveButton("Закрыть",(dialog,which)->{}).create();
        d.setOnShowListener(v->{
            if(d.getWindow()!=null) d.getWindow().setBackgroundDrawable(shape(SURFACE,24));
        });
        d.show();
        if(d.getWindow()!=null) {
            d.getWindow().setBackgroundDrawable(shape(SURFACE,24));
            d.getWindow().setLayout(getResources().getDisplayMetrics().widthPixels-dp(30),-2);
        }
    }

    private void deepAnalyze(AppRecord r) {
        Toast.makeText(this,"Читаем APK локально — это может занять время",Toast.LENGTH_SHORT).show();
        worker.execute(()->{
            try {
                DeepAnalyzer.Result out=DeepAnalyzer.inspect(r.apkPath);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    StringBuilder message=new StringBuilder();
                    message.append("SHA-256 базового APK:\n").append(out.sha256).append("\n\n");
                    message.append("Записей в архиве: ").append(out.entries).append("\n");
                    for(String note:out.notes)message.append("• ").append(note).append("\n");
                    message.append("\nНаличие вложенных архивов — наблюдение, а не доказательство угрозы.");
                    new AlertDialog.Builder(this).setTitle("Глубокая проверка")
                        .setMessage(message.toString()).setPositiveButton("Готово",null).show();
                });
            } catch(Exception e) {
                runOnUiThread(()->{
                    if(!isFinishing()&&!isDestroyed())
                        new AlertDialog.Builder(this).setTitle("Не удалось прочитать APK")
                            .setMessage(String.valueOf(e.getMessage())).setPositiveButton("Закрыть",null).show();
                });
            }
        });
    }


    private void openPrivacyLab(AppRecord record){
        Intent intent=new Intent(this,PrivacyLabActivity.class);
        intent.putExtra("packageName",record.packageName);
        intent.putExtra("label",record.label);
        startActivity(intent);
    }
    private void openDexExplorer(AppRecord record){
        Intent intent=new Intent(this,DexExplorerActivity.class);
        intent.putExtra("packageName",record.packageName);
        intent.putExtra("label",record.label);
        startActivity(intent);
    }
    private void openShizukuActions(AppRecord record){
        if(!ShizukuBridge.available()){
            new AlertDialog.Builder(this).setTitle("Для инструментов нужен Shizuku")
                .setMessage("Установите Shizuku и запустите его через беспроводную отладку или ADB. Root не требуется. После запуска вернитесь и откройте инструменты повторно.")
                .setNegativeButton("Закрыть",null)
                .setPositiveButton("Инструкция Shizuku",(d,w)->openExternal("https://shizuku.rikka.app/guide/setup/"))
                .show();
            return;
        }
        if(!ShizukuBridge.authorized()){
            new AlertDialog.Builder(this).setTitle("Доступ через Shizuku")
                .setMessage("Shizuku запущен, но ASTER ещё не получил разрешение. Нажмите «Разрешить», подтвердите в Shizuku и повторно откройте инструменты приложения.")
                .setNegativeButton("Отмена",null).setPositiveButton("Разрешить",(d,w)->requestShizuku()).show();
            return;
        }
        final String[] actions={
            "Разрешения и состояние пакета (ADB)",
            "AppOps — режимы доступа (ADB)",
            "ОЗУ процесса · dumpsys (ADB)",
            "Пути установленных APK (ADB)",
            "Остановить пользовательское приложение"
        };
        new AlertDialog.Builder(this).setTitle("Shizuku · "+record.label)
            .setItems(actions,(d,index)->{
                int op=10+index;
                if(op==14){
                    if(record.system||record.packageName.equals(getPackageName())){
                        showLong("Операция запрещена","Нельзя принудительно останавливать системные приложения и сам ASTER.");
                        return;
                    }
                    new AlertDialog.Builder(this).setTitle("Остановить "+record.label+"?")
                        .setMessage("Команда «am force-stop» через Shizuku принудительно завершит приложение. Несохранённые данные могут быть потеряны. Это НЕ удаляет его файлы и не очищает ОЗУ навсегда. Продолжить?")
                        .setNegativeButton("Отмена",null)
                        .setPositiveButton("Остановить",(dialog,which)->shizukuPackage(record,op)).show();
                }else shizukuPackage(record,op);
            }).setNegativeButton("Закрыть",null).show();
    }
    private void shizukuPackage(AppRecord record,int op){
        Toast.makeText(this,"Shizuku: запрашиваем сведения через ADB",Toast.LENGTH_SHORT).show();
        worker.execute(()->{
            try{
                String result=ShizukuBridge.packageAction(getApplicationContext(),record.packageName,op);
                runOnUiThread(()->showLong("Shizuku · "+record.label,
                    result.length()>26000?result.substring(0,26000)+"\n… вывод сокращён":result));
            }catch(Exception e){
                runOnUiThread(()->showLong("Shizuku: нет доступа",e.toString()));
            }
        });
    }

    private void reverseEngineer(AppRecord record) {
        Toast.makeText(this,"Статический анализ APK запущен",Toast.LENGTH_SHORT).show();
        worker.execute(()->{
            try{
                ApplicationInfo info=getPackageManager().getApplicationInfo(record.packageName,0);
                List<String> paths=new ArrayList<>();
                paths.add(info.sourceDir);
                if(info.splitSourceDirs!=null)java.util.Collections.addAll(paths,info.splitSourceDirs);
                ApkAuditor.Audit result=ApkAuditor.scan(paths.toArray(new String[0]));
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    LinearLayout panel=column();
                    panel.setPadding(dp(18),dp(12),dp(18),dp(14));
                    String summary="Базовый APK SHA-256: "+result.mainSha256+
                        "\nSplit APK: "+result.splitCount+
                        "\nDEX: "+result.dex.dexFiles+
                        "\nКлассы (идентификаторы): "+result.dex.classCount+
                        "\nМетоды (идентификаторы): "+result.dex.methodIds+
                        "\nНативных библиотек: "+result.nativeLibraries+
                        "\nВложенные архивы: "+result.bundledApks;
                    detailRow(panel,"Сводка",summary);
                    detailRow(panel,"Семейства SDK (не подтверждённые версии)",join(result.dex.possibleLibs,20));
                    detailRow(panel,"API, требующие проверки",join(result.dex.sensitiveApis,30));
                    detailRow(panel,"URL-хосты в строках DEX (не фактические подключения)",join(result.dex.urls,48));
                    detailRow(panel,"Классы (первые 35)",join(result.dex.classNames,35));
                    detailRow(panel,"Методы (первые 45)",join(result.dex.methodNames,45));
                    detailRow(panel,"Нативные .so (первые 25)",join(result.nativeNames,25));
                    detailRow(panel,"Точные Maven-пакеты",join(result.exactMaven,15));
                    detailRow(panel,"Ограничения",join(result.warnings,20));
                    panel.addView(button("Проверить точные версии через OSV/CVE",true,
                        v->{
                            if(result.exactMaven.isEmpty()){
                                Toast.makeText(this,"Нет достоверных координат зависимостей",Toast.LENGTH_LONG).show();
                                return;
                            }
                            new AlertDialog.Builder(this).setTitle("Отправить версии в OSV.dev?")
                                .setMessage("По вашему нажатию будут отправлены названия и версии до 10 Maven-библиотек. Код APK не отправляется. Уязвимости определяются только для точных совпадений.")
                                .setNegativeButton("Отмена",null)
                                .setPositiveButton("Проверить",(d,w)->checkOsv(result)).show();
                        }),fill(12));
                    ScrollView scroll=new ScrollView(this);
                    scroll.addView(panel);
                    AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Исследование APK (статически)")
                        .setView(scroll).setPositiveButton("Закрыть",null).create();
                    dialog.show();
                    if(dialog.getWindow()!=null)dialog.getWindow().setLayout(
                        getResources().getDisplayMetrics().widthPixels-dp(25),-2);
                });
            }catch(Exception e){
                runOnUiThread(()->showLong("Не удалось разобрать APK",e.toString()));
            }
        });
    }

    private String join(java.util.Collection<?> values,int max){
        if(values==null||values.isEmpty())return "Не найдено / недоступно";
        StringBuilder sb=new StringBuilder();int i=0;
        for(Object v:values){
            if(i++>=max)break;
            if(sb.length()>0)sb.append("\n");
            sb.append("• ").append(v);
        }
        return sb.toString();
    }
    private void checkOsv(ApkAuditor.Audit audit){
        Toast.makeText(this,"Запрос OSV выполняется",Toast.LENGTH_SHORT).show();
        worker.execute(()->{
            try{
                List<OsvAdvisor.Finding> found=OsvAdvisor.query(new ArrayList<>(audit.exactMaven));
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    if(found.isEmpty())showLong("OSV: совпадений нет",
                        "Для распознанных точных версий база OSV не вернула идентификаторов уязвимостей. Это не доказывает безопасность остальных библиотек.");
                    else{
                        StringBuilder sb=new StringBuilder();
                        for(OsvAdvisor.Finding x:found)sb.append(x.packageId).append("\n").append(x.ids).append("\n\n");
                        sb.append("Проверьте детали каждой CVE/OSV вручную. Совпадение версии не всегда означает эксплуатируемость в данном APK.");
                        showLong("Совпадения OSV",sb.toString());
                    }
                });
            }catch(Exception e){runOnUiThread(()->showLong("OSV: ошибка",e.toString()));}
        });
    }
    private void showLong(String title,String message){
        if(isFinishing()||isDestroyed())return;
        new AlertDialog.Builder(this).setTitle(title).setMessage(message)
            .setPositiveButton("Закрыть",null).show();
    }
    private void openExternal(String url){
        startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(url)));
    }

    private void startScan() {
        if(scanning)return;
        scanning=true;scanDone=0;scanTotal=0;
        cancelled.set(false);
        render();
        worker.execute(()->{
            try {
                List<AppRecord> fresh=Scanner.scan(getApplicationContext(),cancelled,(done,total)->{
                    runOnUiThread(()->{
                        scanDone=done;scanTotal=total;
                        if(scanning && tab==0)render();
                    });
                });
                runOnUiThread(()->{
                    scanning=false;
                    if(!cancelled.get()) {
                        apps.clear();apps.addAll(fresh);
                        lastScan=System.currentTimeMillis();
                        getPreferences(0).edit().putLong("last_scan",lastScan).apply();
                    }
                    render();
                });
            } catch(Exception e) {
                runOnUiThread(()->{
                    scanning=false;render();
                    if(!isFinishing()&&!isDestroyed())new AlertDialog.Builder(this)
                        .setTitle("Ошибка проверки").setMessage(e.getClass().getSimpleName()+": "+e.getMessage())
                        .setPositiveButton("Закрыть",null).show();
                });
            }
        });
    }

    private void shareReport() {
        StringBuilder b=new StringBuilder("ASTER Guard — локальная проверка\n");
        b.append("Приложений: ").append(apps.size()).append("\n");
        b.append("Дата: ").append(DateFormat.getDateTimeInstance().format(new Date(lastScan))).append("\n");
        for(AppRecord r:apps) {
            if(r.score>=15) {
                b.append("\n").append(r.label).append(" (").append(r.packageName)
                    .append("), ").append(r.score).append("/100\n");
                for(String why:r.reasons)b.append("• ").append(why).append("\n");
            }
        }
        b.append("\nЭто эвристические признаки, не диагноз заражения.");
        Intent i=new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TEXT,b.toString());
        startActivity(Intent.createChooser(i,"Поделиться отчётом"));
    }

    private void showNetwork() {
        sectionTitle(body,"Сеть","Параметры соединения и трафик приложений");
        NetworkReader.Connection c=NetworkReader.connection(this);
        LinearLayout current=card();
        current.addView(spaced("АКТИВНОЕ СОЕДИНЕНИЕ",11,MINT,true),fill(10));
        current.addView(text(c.transport,26,TEXT,true),fill(10));
        current.addView(pill(c.vpn?"VPN активен":"VPN не обнаружен",c.vpn?BLUE:MINT,SURFACE2));
        gap(current,17);
        detailRow(current,"DNS-серверы",c.dns);
        detailRow(current,"Частный DNS",c.privateDns);
        detailRow(current,"Системный прокси",c.proxy);
        detailRow(current,"Тарифицируемое соединение",c.metered?"Да":"Нет");
        body.addView(current,fill(18));

        LinearLayout notice=card();
        notice.addView(text("Что доступно без VPN?",16,TEXT,true),fill(7));
        notice.addView(text("Android может показывать объёмы переданных данных по UID. Содержимое запросов, домены и HTTPS здесь не перехватываются.",13,MUTED,false));
        body.addView(notice,fill(20));

        LinearLayout capture=card();
        capture.addView(text("Анализ дампа сети · PCAP",17,TEXT,true),fill(8));
        capture.addView(text("Импортируйте собственный PCAP. ASTER покажет IP:порт, незашифрованные DNS и HTTP Host, а также TLS SNI, если они есть в пакете. Это не живой VPN-сниффер и не расшифровка HTTPS.",13,MUTED,false),fill(13));
        capture.addView(button("Импортировать PCAP",false,v->pickPcap()));
        body.addView(capture,fill(18));
        LinearLayout live=card();
        live.addView(spaced("ЖИВОЙ ЗАХВАТ · PCAPDROID",11,MINT,true),fill(9));
        live.addView(text("Захват по выбранному приложению",18,TEXT,true),fill(8));
        live.addView(text("Используется установленный PCAPdroid с полноценной VPN-маршрутизацией. ASTER получает только краткие метаданные пакетов через локальный UDP. HTTPS не расшифровывается. PCAPdroid запросит согласие и покажет уведомление.",13,MUTED,false),fill(14));
        if(liveSession!=null){
            PcapInspector.Report snap=liveSession.snapshot();
            String info="Пакетов: "+snap.packets+"   ·   TCP: "+snap.tcp+"   ·   UDP: "+snap.udp+
                    "\nФильтр: "+(liveSession.filter().isEmpty()?"все приложения":liveSession.filter())+
                    "\nDNS/SNI: "+snap.domains.size()+"   ·   IP:порт: "+snap.endpoints.size();
            live.addView(text(info,13,TEXT,false),fill(10));
            if(!liveSession.isRunning())live.addView(text("Локальный приём завершён. Захват PCAPdroid может продолжаться до ручного отключения.",12,AMBER,false),fill(10));
            live.addView(button("Посмотреть сетевые адреса",false,v->showLiveReport()),fill(9));
            live.addView(button("Остановить захват в PCAPdroid",true,v->stopLive()),fill(9));
        }else{
            live.addView(button("Выбрать приложение и начать",true,v->chooseLiveTarget()),fill(9));
        }
        if(!liveWarning.isEmpty())live.addView(text(liveWarning,12,AMBER,false));
        live.addView(text("При выходе из ASTER локальный сбор прекращается. При необходимости остановите VPN также из уведомления PCAPdroid.",11,MUTED,false));
        body.addView(live,fill(20));

        sectionLabel(body,"ТРАФИК ЗА 24 ЧАСА");
        if(!NetworkReader.hasUsageAccess(this)) {
            LinearLayout grant=card();
            grant.addView(text("Нужен доступ к статистике использования",16,TEXT,true),fill(8));
            grant.addView(text("Разрешение предоставляется вручную в настройках Android. Без него нельзя корректно получить счётчики чужих приложений.",13,MUTED,false),fill(15));
            grant.addView(button("Открыть настройки доступа",true,v->{
                startActivity(new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS));
            }));
            body.addView(grant);
        } else {
            body.addView(button(loadingNetwork?"Получаем данные…":"Обновить статистику",true,v->loadNetwork()),fill(15));
            if(!networkError.isEmpty())body.addView(text(networkError,13,AMBER,false),fill(14));
            if(networkUsage.isEmpty() && !loadingNetwork)
                body.addView(text("Для отображения статистики нажмите «Обновить».",13,MUTED,false));
            int shown=0;
            for(NetworkReader.Usage u:networkUsage) {
                if(u.rx+u.tx<=0)continue;
                LinearLayout item=card();
                item.addView(text(u.appName,15,TEXT,true),fill(6));
                item.addView(text("Получено "+formatSize(u.rx)+"   ·   Отправлено "+formatSize(u.tx),12,MUTED,false));
                body.addView(item,fill(9));
                if(++shown>=80)break;
            }
        }
    }

    private void loadNetwork() {
        if(loadingNetwork)return;
        loadingNetwork=true;networkError="";render();
        worker.execute(()->{
            try {
                List<NetworkReader.Usage> values=NetworkReader.last24Hours(getApplicationContext());
                runOnUiThread(()->{
                    loadingNetwork=false;networkUsage=values;
                    if(tab==2)render();
                });
            } catch(Exception e) {
                runOnUiThread(()->{
                    loadingNetwork=false;
                    networkError="Статистика недоступна: "+e.getClass().getSimpleName();
                    if(tab==2)render();
                });
            }
        });
    }


    private void chooseLiveTarget(){
        if(liveSession!=null){showLong("Захват","Завершите предыдущую сессию.");return;}
        java.util.ArrayList<String> titles=new java.util.ArrayList<>();
        java.util.ArrayList<String> targets=new java.util.ArrayList<>();
        titles.add("Все приложения (без атрибуции UID)");targets.add("");
        int cap=0;
        for(AppRecord r:apps){
            if(!r.system && cap++<80){titles.add(r.label+" · "+r.packageName);targets.add(r.packageName);}
        }
        new AlertDialog.Builder(this).setTitle("Что прослушивать?")
            .setItems(titles.toArray(new String[0]),(dialog,index)->beginLive(targets.get(index)))
            .setNegativeButton("Отмена",null).show();
    }

    private void beginLive(String packageName){
        LiveCaptureSession receiver=new LiveCaptureSession();
        try{
            receiver.start(packageName); // bind before external VPN activity starts
            liveSession=receiver;
            liveAuthorized=false;liveWarning="";
            startActivityForResult(LiveCaptureSession.controlIntent("start",packageName),LIVE_START);
        }catch(Exception e){
            receiver.close();liveSession=null;
            new AlertDialog.Builder(this).setTitle("Нужен PCAPdroid")
                .setMessage("Установите PCAPdroid из официального проекта. ASTER никогда не запускает собственный VPN, который может оборвать интернет.\n\n"+e.getClass().getSimpleName())
                .setPositiveButton("Открыть проект",(d,w)->openExternal("https://github.com/emanuele-f/PCAPdroid/releases"))
                .setNegativeButton("Закрыть",null).show();
        }
        if(tab==2)render();
    }
    private void stopLive(){
        if(liveSession==null)return;
        try{startActivityForResult(LiveCaptureSession.controlIntent("stop",null),LIVE_STOP);}
        catch(Exception e){liveWarning="Не удалось отправить команду остановки: "+e;render();}
    }
    private void showLiveReport(){
        if(liveSession==null)return;
        PcapInspector.Report snap=liveSession.snapshot();
        String report="Пакетов: "+snap.packets+
            "\nTCP: "+snap.tcp+" / UDP: "+snap.udp+
            "\nОшибок / пропусков: "+(snap.truncated+liveSession.dropped())+
            "\n\nDNS и TLS SNI:\n"+join(snap.domains,65)+
            "\n\nHTTP Host:\n"+join(snap.hosts,35)+
            "\n\nIP и порты назначения:\n"+join(snap.endpoints.keySet(),100)+
            "\n\n"+snap.note;
        showLong("Живой сетевой анализ",report);
    }

    private void pickPcap(){
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        startActivityForResult(i,PCAP_PICKER);
    }
    @Override protected void onActivityResult(int request,int code,Intent data){
        super.onActivityResult(request,code,data);
        if(request==LIVE_START){
            liveAuthorized=code==RESULT_OK;
            if(!liveAuthorized){
                if(liveSession!=null)liveSession.close();
                liveSession=null;
                liveWarning="Захват отменён или PCAPdroid отказал.";
            }else liveWarning="Захват запущен: откройте интересующее приложение, затем вернитесь к ASTER и нажмите «Посмотреть сетевые адреса».";
            if(tab==2)render();
            return;
        }
        if(request==LIVE_STOP){
            if(code==RESULT_OK){
                if(liveSession!=null)liveSession.close();
                liveSession=null;liveAuthorized=false;liveWarning="Захват остановлен в PCAPdroid.";
            }else liveWarning="PCAPdroid не подтвердил остановку. Откройте его уведомление и остановите захват вручную.";
            if(tab==2)render();
            return;
        }
        if(request!=PCAP_PICKER||code!=RESULT_OK||data==null||data.getData()==null)return;
        final Uri uri=data.getData();
        Toast.makeText(this,"Разбор PCAP локально",Toast.LENGTH_SHORT).show();
        worker.execute(()->{
            try(InputStream input=getContentResolver().openInputStream(uri)){
                if(input==null)throw new java.io.IOException("Файл не открылся");
                PcapInspector.Report r=PcapInspector.parse(input);
                String summary="Пакетов: "+r.packets+
                    "\nIPv4: "+r.ipv4+" / IPv6: "+r.ipv6+
                    "\nTCP: "+r.tcp+" / UDP: "+r.udp+
                    "\nПовреждённых: "+r.truncated+
                    "\n\nDNS / TLS SNI:\n"+join(r.domains,65)+
                    "\n\nHTTP Host:\n"+join(r.hosts,35)+
                    "\n\nНазначения IP:порт:\n"+join(r.endpoints.keySet(),120)+
                    "\n\n"+r.note;
                runOnUiThread(()->showLong("PCAP: направления трафика",summary));
            }catch(Exception e){runOnUiThread(()->showLong("PCAP: ошибка",e.getMessage()));}
        });
    }

    private void showSystem(){
        sectionTitle(body,"Система","Тепловая нагрузка, ОЗУ, батарея и игровые настройки");
        DeviceHealth.Snapshot m=DeviceHealth.snapshot(this);
        LinearLayout snapshot=card();
        snapshot.addView(spaced("ТЕЛЕФОН",11,MINT,true),fill(10));
        snapshot.addView(text(m.model,18,TEXT,true),fill(12));
        detailRow(snapshot,"Батарея",m.batteryPercent<0?"Недоступно":m.batteryPercent+"%"+(m.charging?" · зарядка":""));
        detailRow(snapshot,"Температура аккумулятора",Float.isNaN(m.batteryC)?"Недоступно":String.format(Locale.getDefault(),"%.1f °C",m.batteryC));
        detailRow(snapshot,"Тепловой статус системы",m.thermalStatus<0?"Недоступно":thermalLabel(m.thermalStatus));
        detailRow(snapshot,"Оперативная память",formatSize(m.ramAvailable)+" свободно из "+formatSize(m.ramTotal));
        detailRow(snapshot,"Внутренняя память",formatSize(m.storageAvailable)+" свободно из "+formatSize(m.storageTotal));
        detailRow(snapshot,"Android / патч безопасности",Build.VERSION.RELEASE+" / "+m.patch);
        detailRow(snapshot,"Ядро Linux",m.kernel);
        detailRow(snapshot,"Uptime",m.uptimeMs/3600000+" ч");
        body.addView(snapshot,fill(17));

        sectionLabel(body,"РЕКОМЕНДАЦИИ");
        LinearLayout advice=card();
        for(String reason:m.advice)advice.addView(text("• "+reason,13,TEXT,false),fill(10));
        advice.addView(text("Android не предоставляет обычным приложениям точный CPU/RAM каждого чужого процесса.",12,MUTED,false));
        body.addView(advice,fill(18));

        sectionLabel(body,"ИГРОВОЙ ПРОФИЛЬ");
        LinearLayout game=card();
        boolean active=GameModeSession.active(this);
        game.addView(text(active?"Профиль помечен активным":"Безопасный игровой профиль",17,TEXT,true),fill(7));
        game.addView(text("По вашему запросу ASTER включает режим «Не беспокоить» на срок до 90 минут и восстанавливает настройки. Android не позволяет безопасно «освободить ОЗУ» массовым завершением приложений.",13,MUTED,false),fill(13));
        game.addView(button(active?"Выключить игровой профиль":"Включить игровой профиль",true,v->toggleGameProfile()),fill(10));
        game.addView(button("Настройки батареи и энергосбережения",false,v->openSettings(Settings.ACTION_BATTERY_SAVER_SETTINGS)),fill(10));
        game.addView(button("Управление памятью устройства",false,v->openSettings(Settings.ACTION_INTERNAL_STORAGE_SETTINGS)),fill(10));
        game.addView(button("Очистить только кэш ASTER Guard",false,v->clearOwnCache()));
        body.addView(game,fill(18));

        sectionLabel(body,"АКТИВНОСТЬ ПРИЛОЖЕНИЙ · 24 ЧАСА");
        LinearLayout activity=card();
        activity.addView(text("Время на переднем плане ≠ загрузка CPU",14,TEXT,true),fill(8));
        if(!NetworkReader.hasUsageAccess(this)){
            activity.addView(text("Для статистики активности нужно разрешение «Доступ к использованию».",13,MUTED,false),fill(10));
            activity.addView(button("Открыть доступ",false,v->openSettings(Settings.ACTION_USAGE_ACCESS_SETTINGS)));
        }else{
            activity.addView(button(loadingForeground?"Считывание…":"Обновить активность",false,v->loadForeground()),fill(12));
            for(DeviceHealth.AppActivity a:foregroundApps){
                activity.addView(text(a.name+" · "+a.foregroundMs/60000+" мин",13,TEXT,false),fill(6));
            }
        }
        body.addView(activity,fill(18));

        sectionLabel(body,"SHIZUKU · ДОПОЛНИТЕЛЬНАЯ ДИАГНОСТИКА");
        LinearLayout shizuku=card();
        shizuku.addView(text(ShizukuBridge.status(),14,TEXT,true),fill(10));
        shizuku.addView(text("Запустите Shizuku через беспроводную отладку или ADB, затем разрешите доступ ASTER. В карточке любого пользовательского приложения появятся диагностика пакета, AppOps, сведения о памяти и остановка по подтверждению. Это ADB/shell, не root и не debugger чужого процесса.",12,MUTED,false),fill(12));
        if(!ShizukuBridge.available()){
            shizuku.addView(button("Как установить и запустить Shizuku",false,v->openExternal("https://shizuku.rikka.app/guide/setup/")),fill(10));
        }else if(!ShizukuBridge.authorized()){
            shizuku.addView(button("Разрешить Shizuku",false,v->requestShizuku()),fill(10));
        }else{
            shizuku.addView(button("CPU: снимок TOP через ADB",false,v->shizukuRead("cpu")),fill(10));
            shizuku.addView(button("Процессы и RSS (ADB)",false,v->shizukuRead("processes")),fill(10));
            shizuku.addView(button("Подробная память (ADB)",false,v->shizukuRead("memory")),fill(10));
        }
        body.addView(shizuku);
    }
    private String thermalLabel(int status){
        switch(status){
            case 0:return "Нормальный / ограничений нет";
            case 1:return "Незначительный";
            case 2:return "Умеренный";
            case 3:return "Существенный";
            case 4:return "Критический";
            case 5:return "Аварийный";
            case 6:return "Угроза выключения";
            default:return "Код "+status;
        }
    }
    private void loadForeground(){
        if(loadingForeground)return;
        loadingForeground=true;
        worker.execute(()->{
            List<DeviceHealth.AppActivity> values=DeviceHealth.foreground24h(getApplicationContext());
            runOnUiThread(()->{
                loadingForeground=false;foregroundApps.clear();foregroundApps.addAll(values);
                if(tab==3)render();
            });
        });
    }
    private void openSettings(String action){
        try{startActivity(new Intent(action));}
        catch(Exception e){startActivity(new Intent(Settings.ACTION_SETTINGS));}
    }
    private void requestShizuku(){
        try{
            if(ShizukuBridge.available())Shizuku.requestPermission(ShizukuBridge.REQUEST_CODE);
            else openExternal("https://shizuku.rikka.app/");
        }catch(Throwable e){showLong("Shizuku",String.valueOf(e));}
    }
    private void shizukuRead(String type){
        Toast.makeText(this,"Shizuku: диагностика",Toast.LENGTH_SHORT).show();
        worker.execute(()->{
            try{
                String text=ShizukuBridge.diagnostics(getApplicationContext(),type);
                runOnUiThread(()->showLong("ADB · "+type,text.length()>16000?text.substring(0,16000)+"\n… вывод сокращён":text));
            }catch(Exception e){runOnUiThread(()->showLong("Shizuku: отказ",e.toString()));}
        });
    }
    private void toggleGameProfile(){
        if(GameModeSession.active(this)){
            GameModeSession.stop(this);render();return;
        }
        NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(nm==null)return;
        if(!nm.isNotificationPolicyAccessGranted()){
            new AlertDialog.Builder(this).setTitle("Разрешение «Не беспокоить»")
                .setMessage("Для включения безопасного игрового профиля нужно вручную разрешить изменение режима уведомлений.")
                .setNegativeButton("Отмена",null)
                .setPositiveButton("Открыть настройки",(d,w)->openSettings(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS))
                .show();
            return;
        }
        try{
            GameModeSession.start(this);
            clearOwnCache(); // Only ASTER's own temporary cache; not system RAM.
            render();
        }catch(Exception e){showLong("Игровой режим",e.toString());}
    }
    private void clearOwnCache(){
        java.io.File dir=getCacheDir();
        long[] deleted=new long[1];
        clearCacheRecursively(dir,deleted,0);
        Toast.makeText(this,"Кэш ASTER: очищено "+formatSize(deleted[0]),Toast.LENGTH_LONG).show();
    }
    private void clearCacheRecursively(java.io.File dir,long[] total,int depth){
        if(depth>8||dir==null)return;
        java.io.File[] files=dir.listFiles();
        if(files==null)return;
        for(java.io.File f:files){
            if(f.isDirectory())clearCacheRecursively(f,total,depth+1);
            else{
                long size=f.length();
                if(f.delete())total[0]+=size;
            }
        }
    }

    private void showSettings() {
        sectionTitle(body,"Настройки","Приватность и возможности ASTER Guard");
        LinearLayout privacy=card();
        privacy.addView(spaced("ПРИВАТНОСТЬ",11,MINT,true),fill(12));
        privacy.addView(text("Только локальный анализ",19,TEXT,true),fill(8));
        privacy.addView(text("Сканирование APK и PCAP проводится локально. Интернет используется при запуске для проверки GitHub Releases, а по вашему отдельному согласию — для запросов координат Maven-зависимостей в OSV.dev. Данные APK не загружаются.",13,MUTED,false));
        body.addView(privacy,fill(17));

        LinearLayout power=card();
        power.addView(spaced("ПРОИЗВОДИТЕЛЬНОСТЬ",11,BLUE,true),fill(12));
        power.addView(text("Ноль постоянных фоновых сканеров",17,TEXT,true),fill(9));
        power.addView(text("Лёгкая проверка читает метаданные приложений. Расчёт хэша файла и разбор содержимого APK запускаются отдельно. Никаких фоновых сетевых опросов, служб VPN и постоянных уведомлений.",13,MUTED,false));
        body.addView(power,fill(17));

        LinearLayout limits=card();
        limits.addView(spaced("ОГРАНИЧЕНИЯ",11,AMBER,true),fill(12));
        limits.addView(text("Не заменяет полноценную антивирусную защиту",17,TEXT,true),fill(8));
        limits.addView(text("DEX/Smali показывает инструкции APK, но не исходный Java-код и не живую трассировку чужого процесса. Живой анализ сети требует отдельно установленного PCAPdroid. HTTPS не расшифровывается. Shizuku даёт некоторые ADB-команды, но не root.",13,MUTED,false));
        body.addView(limits,fill(17));

        LinearLayout about=card();
        about.addView(text("ASTER Guard 0.7.2",16,TEXT,true),fill(7));
        about.addView(text("Java · Android 7+ · ARMv7 / ARM64 · DEX/Smali, Shizuku",12,MUTED,false),fill(11));
        if(newRelease!=null){
            about.addView(button("Доступно обновление "+newRelease.version,true,v->openExternal(newRelease.url)),fill(10));
        }
        about.addView(text("Проверка GitHub выполняется только при входе в приложение; установка APK — только по вашему действию.",12,MUTED,false),fill(9));
        about.addView(button("Открыть релизы GitHub",false,v->openExternal("https://github.com/crakacr-alt/ASTER-Guard/releases")),fill(9));
        about.addView(button("Исходный код на GitHub",false,v->{
            startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse("https://github.com/crakacr-alt/ASTER-Guard")));
        }));
        body.addView(about);
    }

    private void navigation() {
        LinearLayout nav=row();
        nav.setPadding(dp(12),dp(9),dp(12),dp(9));
        nav.setBackgroundColor(0xFF0E1420);
        String[] icons={"◈","▣","⌁","◉","⚙"};
        String[] labels={"Обзор","APK","Сеть","Система","Опции"};
        for(int i=0;i<labels.length;i++) {
            final int index=i;
            LinearLayout item=column();
            item.setGravity(Gravity.CENTER);
            item.setPadding(dp(4),dp(8),dp(4),dp(6));
            item.setBackground(ripple(i==tab?SURFACE2:0xFF0E1420,18));
            TextView icon=text(icons[i],21,i==tab?MINT:MUTED,true);
            icon.setGravity(Gravity.CENTER);
            item.addView(icon);
            TextView label=text(labels[i],10,i==tab?TEXT:MUTED,i==tab);
            label.setGravity(Gravity.CENTER);
            item.addView(label);
            item.setOnClickListener(v->{if(tab!=index){tab=index;render();}});
            nav.addView(item,new LinearLayout.LayoutParams(0,-2,1));
        }
        root.addView(nav);
    }

    private final class Ring extends View {
        private final Paint p=new Paint(Paint.ANTI_ALIAS_FLAG);
        private final RectF rect=new RectF();
        private float progress=1f;
        private boolean busy;
        private int metric;
        Ring(){super(MainActivity.this);}
        void setMode(boolean scanning,float progress,int metric) {
            this.busy=scanning;this.progress=Math.max(0f,Math.min(1f,progress));
            this.metric=metric;
            invalidate();
        }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            float w=getWidth(),h=getHeight(),stroke=dp(11),padding=dp(15);
            rect.set(padding,padding,w-padding,h-padding);
            p.setStyle(Paint.Style.STROKE);p.setStrokeCap(Paint.Cap.ROUND);
            p.setStrokeWidth(stroke);p.setColor(0xFF35445A);
            canvas.drawArc(rect,-90,360,false,p);
            p.setColor(MINT);
            canvas.drawArc(rect,-90,360*(busy?progress:1f),false,p);
            p.setStyle(Paint.Style.FILL);p.setTypeface(Typeface.create("sans-serif",Typeface.BOLD));
            p.setTextAlign(Paint.Align.CENTER);p.setTextSize(dp(40));p.setColor(TEXT);
            String large=busy?Math.round(progress*100)+"%":String.valueOf(metric);
            canvas.drawText(large,w/2,h/2+dp(7),p);
            p.setTextSize(dp(11));p.setColor(MUTED);
            p.setTypeface(Typeface.create("sans-serif-medium",Typeface.NORMAL));
            canvas.drawText(busy?"ПРОГРЕСС":"ФЛАГИ РИСКА",w/2,h/2+dp(27),p);
        }
    }
}
