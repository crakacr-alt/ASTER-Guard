package dev.aster.guard;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.database.Cursor;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.ProgressBar;
import android.view.View;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** User-selected document checker with Android Storage Access Framework, NO storage permissions. */
public final class FileScanActivity extends Activity {
    private static final int PICK=4062, BG=0xff0f1523, SURFACE=0xff1a2534, TEXT=0xffedf6fa,
        MUTED=0xffa4b8c8, MINT=0xff8cecd4, AMBER=0xffffca82, RED=0xffff9292;
    private static final long MAX_TEMP_APK=96L*1024*1024;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final AtomicBoolean cancelled=new AtomicBoolean(false);
    private LinearLayout root,content;
    private TextView progress;
    private ProgressBar bar;
    private Uri picked;
    private FileInspector.Report report;
    private String displayName="",mime="";
    private long size=-1;
    private boolean running=false;
    private File stagedApk;
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        build();
    }
    private TextView label(String s,int font,int color){
        TextView t=new TextView(this);t.setText(s);t.setTextSize(font);t.setTextColor(color);
        t.setPadding(dp(8),dp(8),dp(8),dp(8));return t;
    }
    private Button action(String s,Runnable runnable){
        Button b=new Button(this);b.setText(s);b.setTextSize(13);b.setAllCaps(false);
        b.setOnClickListener(v->runnable.run());return b;
    }
    private void add(String s,int font,int color){content.addView(label(s,font,color));}
    private void build(){
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);root.setPadding(dp(12),dp(8),dp(12),dp(4));
        setContentView(root);
        LinearLayout top=new LinearLayout(this);top.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(top);
        top.addView(action("‹ Назад",this::finish),new LinearLayout.LayoutParams(dp(98),dp(44)));
        TextView heading=label("Проверка файла",21,MINT);
        heading.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        top.addView(heading,new LinearLayout.LayoutParams(0,-2,1));
        ScrollView scroll=new ScrollView(this);
        content=new LinearLayout(this);content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(4),dp(8),dp(4),dp(25));
        scroll.addView(content);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        render();
    }
    private void render(){
        content.removeAllViews();
        add("Проверка без установки и запуска",20,TEXT);
        add("Выберите любой файл: APK, EXE, PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX/PPS, PNG/JPEG, ZIP/JAR, RAR/7z или другой. Чтение только локально через системный выбор файла. Никакой загрузки в облако.",13,MUTED);
        content.addView(action("Выбрать файл из памяти",this::pick));
        if(picked==null){
            add("ASTER проверяет сигнатуру, SHA-256 и некоторые опасные элементы. Это эвристика, не облачный антивирус и не гарантия отсутствия угроз.",13,AMBER);
            return;
        }
        add("Файл: "+displayName,17,TEXT);
        add("Размер: "+(size<0?"не сообщён":formatSize(size))+" · MIME: "+mime,12,MUTED);
        if(running){
            add("Проверка выполняется без запуска файла...",15,MINT);
            bar=new ProgressBar(this);
            content.addView(bar);
            progress=label("Читаем файл...",13,MUTED);content.addView(progress);
            content.addView(action("Отменить",()->cancelled.set(true)));
            return;
        }
        if(report==null)return;
        final FileInspector.Report r=report;
        add("Формат по сигнатуре: "+r.format,17,TEXT);
        int color=stateColor(r);
        add(r.confidence(),15,color);
        add("Прочитано: "+formatSize(r.bytesRead)+(r.complete?"":" (неполностью)"),13,MUTED);
        add("SHA-256:\n"+(r.sha256.isEmpty()?"Не вычислен полностью":r.sha256),12,MINT);
        if(r.archive)add("ZIP-записей: "+r.entries+" · DEX: "+r.classesDex+
            " · .so: "+r.nativeLibraries+" · вложений с кодом: "+r.embeddedExecutables+
            " · VBA: "+r.macroFiles,13,MUTED);
        if(r.findings.isEmpty())add("Известные структурные индикаторы не обнаружены. Отсутствие признаков НЕ означает, что файл безопасен.",13,MUTED);
        for(FileInspector.Finding f:r.findings){
            LinearLayout item=new LinearLayout(this);item.setOrientation(LinearLayout.VERTICAL);
            item.setPadding(dp(8),dp(8),dp(8),dp(8));item.setBackgroundColor(SURFACE);
            TextView heading=label((f.severity==2?"! ":f.severity==1?"⚠ ":"• ")+f.title,14,
                f.severity==2?RED:f.severity==1?AMBER:MINT);
            heading.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
            item.addView(heading);item.addView(label(f.explanation,12,MUTED));
            LinearLayout spacer=new LinearLayout(this);spacer.setPadding(0,0,0,dp(7));
            spacer.addView(item,new LinearLayout.LayoutParams(-1,-2));content.addView(spacer);
        }
        if(r.apk){
            add("APK ещё НЕ установлен. Для просмотра DEX-кода можно создать временную копию в закрытом кэше ASTER без установки.",13,MUTED);
            content.addView(action("Исследовать код APK (DEX / Smali)",this::stageApk));
        }
        content.addView(action("Копировать отчёт",()->{
            ClipboardManager clipboard=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
            if(clipboard!=null)clipboard.setPrimaryClip(ClipData.newPlainText("ASTER · проверка файла",reportText(r)));
        }));
        content.addView(action("Поделиться отчётом",()->{
            Intent intent=new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");intent.putExtra(Intent.EXTRA_TEXT,reportText(r));
            startActivity(Intent.createChooser(intent,"Отчёт ASTER"));
        }));
        add("Пределы: общий размер до 512 МиБ, распаковка ZIP до 64 МиБ и не более 1200 записей. Внутри RAR/7z и старых DOC/PPT/XLS полноценный анализ макросов не выполняется. PDF может скрывать код в сжатых потоках.",12,MUTED);
    }
    private int stateColor(FileInspector.Report r){
        if(!r.complete||r.zipPartial)return AMBER;
        for(FileInspector.Finding f:r.findings)if(f.severity==2)return RED;
        for(FileInspector.Finding f:r.findings)if(f.severity==1)return AMBER;
        return MINT;
    }
    private String reportText(FileInspector.Report r){
        StringBuilder sb=new StringBuilder();
        sb.append("ASTER Guard · локальный анализ файла\n")
            .append("Файл: ").append(r.name).append("\n")
            .append("Тип: ").append(r.format).append("\n")
            .append("Прочитано: ").append(r.bytesRead).append(" байт\n")
            .append("SHA-256: ").append(r.sha256.isEmpty()?"неполный":r.sha256).append("\n")
            .append("Оценка: ").append(r.confidence()).append("\n");
        for(FileInspector.Finding f:r.findings)
            sb.append("\n").append(f.title).append("\n").append(f.explanation).append("\n");
        sb.append("\nВывод основан на статических маркерах, не является проверкой сигнатур всех известных угроз.");
        return sb.toString();
    }
    private static String formatSize(long size){
        if(size<0)return "недоступно";
        if(size<1024)return size+" Б";
        if(size<1024*1024)return String.format(Locale.ROOT,"%.1f КБ",size/1024.0);
        return String.format(Locale.ROOT,"%.1f МБ",size/1048576.0);
    }
    private void pick(){
        if(running){cancelled.set(true);return;}
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(i,PICK);
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request!=PICK||result!=RESULT_OK||data==null||data.getData()==null)return;
        picked=data.getData();report=null;cancelled.set(false);
        size=-1;displayName="Выбранный файл";mime=getContentResolver().getType(picked);
        if(mime==null)mime="application/octet-stream";
        try(Cursor cursor=getContentResolver().query(picked,new String[]{
            OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE},null,null,null)){
            if(cursor!=null&&cursor.moveToFirst()){
                int nameCol=cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if(nameCol>=0&&!cursor.isNull(nameCol))displayName=cursor.getString(nameCol);
                int sizeCol=cursor.getColumnIndex(OpenableColumns.SIZE);
                if(sizeCol>=0&&!cursor.isNull(sizeCol))size=cursor.getLong(sizeCol);
            }
        }catch(Exception ignored){}
        analyze();
    }
    private void analyze(){
        final Uri target=picked;
        final String name=displayName,fileMime=mime;
        final long fileSize=size;
        running=true;render();
        worker.execute(()->{
            FileInspector.Report result=null;String error=null;
            try(InputStream first=getContentResolver().openInputStream(target)){
                if(first==null)throw new IOException("Источник не вернул поток файла");
                InputStream second=null;
                try{second=getContentResolver().openInputStream(target);}catch(Exception ignored){}
                try(InputStream another=second){
                    final long[] previous={0};
                    result=FileInspector.analyze(first,another,name,fileMime,fileSize,
                        cancelled::get,bytes->{
                            if(bytes-previous[0]>=4*1024*1024){
                                previous[0]=bytes;
                                runOnUiThread(()->{
                                    if(progress!=null&&running)progress.setText("Прочитано "+formatSize(bytes));
                                });
                            }
                        });
                }
            }catch(Exception e){error=e.getMessage();}
            final FileInspector.Report finalResult=result;
            final String finalError=error;
            runOnUiThread(()->{
                if(isFinishing()||isDestroyed())return;
                running=false;
                if(!target.equals(picked))return;
                report=finalResult;render();
                if(finalError!=null)new AlertDialog.Builder(this)
                    .setTitle("Проверка не выполнена")
                    .setMessage(finalError)
                    .setPositiveButton("Закрыть",null).show();
            });
        });
    }
    private void stageApk(){
        if(report==null||!report.apk||picked==null||running)return;
        if(size>MAX_TEMP_APK){
            message("APK больше 96 МиБ", "Для экономии памяти ASTER не копирует такой APK в кэш. Основная проверка уже завершена.");return;
        }
        running=true;render();
        final Uri target=picked;
        worker.execute(()->{
            File tmp=new File(getCacheDir(),"selected-apk-review.apk");
            String error=null;long total=0;
            try(InputStream in=getContentResolver().openInputStream(target);
                OutputStream out=new FileOutputStream(tmp,false)){
                if(in==null)throw new IOException("APK недоступен");
                byte[] b=new byte[64*1024];int n;
                while((n=in.read(b))!=-1){
                    if(cancelled.get()||total+n>MAX_TEMP_APK)throw new IOException("Отменено или APK превышает лимит 96 МиБ");
                    out.write(b,0,n);total+=n;
                }
            }catch(Exception e){error=e.getMessage();tmp.delete();}
            final String finalError=error;
            runOnUiThread(()->{
                running=false;if(isFinishing()||isDestroyed())return;render();
                if(finalError!=null){message("Не удалось подготовить APK",finalError);return;}
                stagedApk=tmp;
                String packageName="unknown";
                try{
                    PackageInfo info=getPackageManager().getPackageArchiveInfo(tmp.getAbsolutePath(),0);
                    if(info!=null&&info.packageName!=null)packageName=info.packageName;
                }catch(Exception ignored){}
                Intent intent=new Intent(this,DexExplorerActivity.class);
                intent.putExtra("archivePath",tmp.getAbsolutePath());
                intent.putExtra("packageName",packageName);
                intent.putExtra("label",displayName+" · без установки");
                startActivity(intent);
            });
        });
    }
    private void message(String title,String body){
        new AlertDialog.Builder(this).setTitle(title).setMessage(body)
            .setPositiveButton("Закрыть",null).show();
    }
    @Override protected void onDestroy(){
        cancelled.set(true);worker.shutdownNow();
        super.onDestroy();
    }
}
