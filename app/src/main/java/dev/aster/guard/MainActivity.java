package dev.aster.guard;

import android.app.Activity;
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
    private String query="",networkError="";
    private long lastScan=0;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        if (Build.VERSION.SDK_INT>=29) getWindow().setNavigationBarContrastEnforced(false);
        lastScan=getPreferences(0).getLong("last_scan",0);
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
        render();
    }

    @Override protected void onDestroy() {
        cancelled.set(true);
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

    private void showApps() {
        sectionTitle(body,"Приложения","Подробности, разрешения и цифровые подписи");
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
        box.addView(button("Глубокий анализ APK + SHA-256",true,v->deepAnalyze(r)),fill(10));
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

    private void showSettings() {
        sectionTitle(body,"Настройки","Приватность и возможности ASTER Guard");
        LinearLayout privacy=card();
        privacy.addView(spaced("ПРИВАТНОСТЬ",11,MINT,true),fill(12));
        privacy.addView(text("Только локальный анализ",19,TEXT,true),fill(8));
        privacy.addView(text("У приложения нет разрешения INTERNET. Сведения о пакетах, подписях и разрешениях остаются на устройстве. Отчёт передаётся только если вы сами нажмёте «Поделиться».",13,MUTED,false));
        body.addView(privacy,fill(17));

        LinearLayout power=card();
        power.addView(spaced("ПРОИЗВОДИТЕЛЬНОСТЬ",11,BLUE,true),fill(12));
        power.addView(text("Ноль постоянных фоновых сканеров",17,TEXT,true),fill(9));
        power.addView(text("Лёгкая проверка читает метаданные приложений. Расчёт хэша файла и разбор содержимого APK запускаются отдельно. Никаких фоновых сетевых опросов, служб VPN и постоянных уведомлений.",13,MUTED,false));
        body.addView(power,fill(17));

        LinearLayout limits=card();
        limits.addView(spaced("ОГРАНИЧЕНИЯ",11,AMBER,true),fill(12));
        limits.addView(text("Не заменяет полноценную антивирусную защиту",17,TEXT,true),fill(8));
        limits.addView(text("Текущая версия не содержит проверенной базы вредоносного ПО, динамической песочницы, перехвата пакетов или дешифратора HTTPS. Android не предоставляет стороннему приложению бесконтрольный доступ к данным других приложений.",13,MUTED,false));
        body.addView(limits,fill(17));

        LinearLayout about=card();
        about.addView(text("ASTER Guard 0.2.0",16,TEXT,true),fill(7));
        about.addView(text("Java · Android 6+ · arm32 / arm64 · без ABI-специфичных библиотек",12,MUTED,false),fill(11));
        about.addView(button("Исходный код на GitHub",false,v->{
            startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse("https://github.com/crakacr-alt/ASTER-Guard")));
        }));
        body.addView(about);
    }

    private void navigation() {
        LinearLayout nav=row();
        nav.setPadding(dp(12),dp(9),dp(12),dp(9));
        nav.setBackgroundColor(0xFF0E1420);
        String[] icons={"◈","▣","⌁","⚙"};
        String[] labels={"Обзор","Приложения","Сеть","О приложении"};
        for(int i=0;i<4;i++) {
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
            RectF rect=new RectF(padding,padding,w-padding,h-padding);
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
