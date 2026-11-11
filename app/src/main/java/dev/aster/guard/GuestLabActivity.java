package dev.aster.guard;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Aster UI for an EXTERNAL rooted guest emulator. Root never touches this device.
 * The Android app has no embedded full-system VM, arbitrary ADB shell or in-app root.
 * Pairing requires a manually verified TLS SHA-256 certificate pin and bearer token.
 */
public final class GuestLabActivity extends Activity {
    private static final int BG=0xff0f1523,TEXT=0xffedf6fa,MINT=0xff8cecd4,
        MUTED=0xffa4b8c8,AMBER=0xffffca82;
    private static final int PICK_APK=5041,SAVE_HEAP=5042;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private GuestLabClient lab;
    private LinearLayout root,body;
    private EditText serverInput,pinInput,tokenInput;
    private String server="",fingerprint="",token="";
    private JSONObject status;
    private final List<String> packages=new ArrayList<>();
    private String selected="",output="",outputTitle="Отчёт",heapId="",heapHash="",heapName="";
    private boolean busy;
    private int dp(int x){return Math.round(getResources().getDisplayMetrics().density*x);}

    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);root.setPadding(dp(12),dp(8),dp(12),0);
        setContentView(root);
        LinearLayout nav=new LinearLayout(this);nav.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(nav,new LinearLayout.LayoutParams(-1,dp(52)));
        nav.addView(button("‹ Назад",this::finish),new LinearLayout.LayoutParams(dp(98),-2));
        nav.addView(text("ASTER · Android Lab",19,MINT),new LinearLayout.LayoutParams(0,-2,1));
        ScrollView scroller=new ScrollView(this);
        body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(0,dp(8),0,dp(32));
        scroller.addView(body);
        root.addView(scroller,new LinearLayout.LayoutParams(-1,0,1));
        render();
    }
    private TextView text(String s,int font,int color){
        TextView t=new TextView(this);t.setText(s);t.setTextSize(font);t.setTextColor(color);
        t.setPadding(dp(7),dp(8),dp(7),dp(8));return t;
    }
    private Button button(String label,Runnable action){
        Button b=new Button(this);b.setText(label);b.setTextSize(12);
        b.setAllCaps(false);b.setOnClickListener(v->action.run());return b;
    }
    private void line(String v,int size,int color){body.addView(text(v,size,color));}
    private void heading(String t){
        TextView v=text(t,17,MINT);
        v.setTypeface(Typeface.DEFAULT,Typeface.BOLD);body.addView(v);
    }
    private EditText input(String hint,String value,boolean secret){
        EditText e=new EditText(this);e.setSingleLine(true);
        e.setTextColor(TEXT);e.setHintTextColor(MUTED);e.setTextSize(14);
        e.setHint(hint);e.setText(value);
        e.setInputType(secret?InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD:
            InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_URI);
        return e;
    }
    private void render(){
        if(isDestroyed()||isFinishing())return;
        body.removeAllViews();
        line("Гостевая Android 7+ · отдельная лаборатория",19,TEXT);
        line("Весь пульт управления расположен в ASTER. Сам Android Emulator с root работает на вашем отдельном ПК/сервере, "+
             "а НЕ внутри этого APK или основного телефона. Не запускайте подозрительный APK на основной ОС.",13,AMBER);
        if(lab==null){
            heading("Защищённое подключение к лаборатории");
            line("Требуется HTTPS-адрес частного лабораторного моста, SHA-256 его сертификата и секретный токен. "+
                 "Проверьте отпечаток вручную. Не открывайте мост в публичный интернет.",12,MUTED);
            serverInput=input("https://192.168.x.x:8742",server.isEmpty()?"https://127.0.0.1:8742":server,false);
            pinInput=input("SHA-256 сертификата · 64 символа",fingerprint,false);
            tokenInput=input("Токен сопряжения",token,true);
            body.addView(serverInput);body.addView(pinInput);body.addView(tokenInput);
            body.addView(button("Подключиться по HTTPS",this::pair));
            line("Настройка лаборатории: в исходниках репозитория /lab/. Гостевой образ выбирается при "+
                 "запуске Android Emulator на ПК: Android API 24+, x86 или x86_64, rootable AOSP.",12,MUTED);
            return;
        }
        line(busy?"Выполняется команда в отдельном потоке…":"Мост сопряжён · TLS-пин проверяется при каждом запросе",13,busy?AMBER:MINT);
        body.addView(button("Проверить статус гостевой Android",()->request("Статус Android",()->lab.get("/v1/status"),true)));
        body.addView(button("Отключить лабораторию",()->{
            lab=null;status=null;packages.clear();selected="";heapId="";token="";render();
        }));
        if(status!=null){
            heading("Гость и root");
            line("Android "+status.optString("android","?")+" · "+status.optString("architecture","?")+
                 "\nADB-гость: "+status.optString("guest","?")+" · root: "+
                 (status.optBoolean("root")?"подтверждён":"нет")+
                 "\nПакет: "+(selected.isEmpty()?"не выбран":selected)+
                 "\nPID: "+status.optString("pid","—")+
                 "\nСеть: "+status.optString("network_isolation","не проверено"),13,TEXT);
            line("СЕТЕВАЯ ИЗОЛЯЦИЯ: без проверенного firewall/namespace хоста безопасный запуск "+
                 "реального вредоносного ПО не гарантируется. Переключатель сети намеренно не "+
                 "имитирует защиту.",12,AMBER);
        }
        heading("Гостевая сеть (мягкие переключатели)");
        body.addView(button("Отключить Wi-Fi и мобильные данные в госте",()->network(false)));
        body.addView(button("Включить Wi-Fi и мобильные данные в госте",()->network(true)));
        line("Это настройки гостевой Android, НЕ гарантированная изоляция вируса. "+
             "Для запуска настоящего вредоносного APK нужна отдельная изоляция "+
             "сетевого выхода на лабораторном ПК.",12,AMBER);
        heading("Гостевые APK и выбор процесса");
        body.addView(button("Обновить список гостевых приложений",this::refreshPackages));
        body.addView(button("Выбрать пакет для анализа",this::choosePackage));
        body.addView(button("Установить APK в гостевой Android",this::confirmImport));
        body.addView(button("Запустить выбранное приложение",()->{
            new AlertDialog.Builder(this).setTitle("Запуск APK в гостевой Android")
                .setMessage("Подтвердите, что это ваш лабораторный эмулятор, а не основной телефон. "+
                    "Сеть гостя может выходить через NAT даже при выключенном Wi-Fi! "+
                    "Не запускайте неизвестный вредоносный APK без проверенного "+
                    "сетевого ограничения на лабораторном хосте.")
                .setNegativeButton("Отмена",null)
                .setPositiveButton("Запустить в госте",(d,w)->request(
                    "Запуск гостевого APK",()->lab.post("/v1/start",new JSONObject()),true))
                .show();
        }));
        body.addView(button("Остановить выбранное приложение",()->{
            new AlertDialog.Builder(this).setTitle("Остановить процесс гостя?")
                .setMessage("Только выбранный пакет в эмуляторе; несохранённые данные внутри гостя могут быть потеряны.")
                .setNegativeButton("Отмена",null)
                .setPositiveButton("Остановить",(d,w)->request("Остановка",()->lab.post("/v1/stop",new JSONObject()),true))
                .show();
        }));
        heading("Live-трассировка · выбранный PID");
        body.addView(button("Live: начать запись Logcat выбранного PID",()->request(
            "Live Logcat включён",()->lab.post("/v1/trace/start",new JSONObject()),false)));
        body.addView(button("Live: показать накопленные события",()->request(
            "Live Logcat · накопленные события",()->lab.get("/v1/trace"),false)));
        body.addView(button("Live: остановить запись Logcat",()->request(
            "Live Logcat остановлен",()->lab.post("/v1/trace/stop",new JSONObject()),false)));
        body.addView(button("Logcat · последние записи PID",()->request(
            "Logcat выбранного процесса",()->lab.get("/v1/logs"),false)));
        body.addView(button("Память /proc и native backtrace",()->request(
            "PID / proc / debuggerd",()->lab.get("/v1/process"),false)));
        heading("JDWP · точки останова и пошаговое исполнение");
        line("Доступен для Java-процессов с поддержкой JDWP в гостевом Android. "+
             "Даже гостевой root не гарантирует подключение к приложению, собранному без отладки. "+
             "Нативный LLDB пока не подключён.",12,MUTED);
        body.addView(button("JDWP: подключить отладчик",()->request(
            "JDWP attach",()->lab.post("/v1/debug/attach",new JSONObject()),false)));
        body.addView(button("JDWP: вывести состояние/ответ",()->request(
            "JDWP live output",()->lab.get("/v1/debug"),false)));
        LinearLayout commands=new LinearLayout(this);commands.setOrientation(LinearLayout.VERTICAL);
        body.addView(commands);
        String[] names={"Потоки","Стек вызовов","Классы","Пауза","Продолжить","Шаг в метод","Шаг через"};
        String[] ids={"threads","where","classes","suspend","resume","step","next"};
        for(int i=0;i<names.length;i++){
            final String cmd=ids[i];
            commands.addView(button("JDWP · "+names[i],()->debugCommand(cmd,"")));
        }
        body.addView(button("JDWP · установить breakpoint класс:строка",()->breakpoint("break")));
        body.addView(button("JDWP · снять breakpoint класс:строка",()->breakpoint("clear")));
        body.addView(button("JDWP · отключить отладчик",()->request(
            "JDWP detach",()->lab.post("/v1/debug/detach",new JSONObject()),false)));
        heading("Дамп выбранного приложения");
        line("HPROF снимается с конкретного гостевого процесса. Android может отказать, если "+
             "процесс не поддерживает heap dump. Дамп может содержать секреты и личные данные. "+
             "Никакого автоматического облачного экспорта.",12,AMBER);
        body.addView(button("Снять HPROF-дамп (до 128 МиБ)",this::confirmDump));
        if(!heapId.isEmpty())body.addView(button("Сохранить HPROF через проводник Android",this::saveDump));
        heading("Журнал лаборатории");
        body.addView(button("Запросить журнал команд и сеанса",()->request(
            "События лаборатории",()->lab.get("/v1/events"),false)));
        if(!output.isEmpty()){
            heading(outputTitle);
            body.addView(button("Скопировать отчёт",()->{
                ClipboardManager cb=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
                if(cb!=null)cb.setPrimaryClip(ClipData.newPlainText("ASTER guest lab",output));
            }));
            TextView view=text(output.length()>32000?output.substring(0,32000)+"\n[обрезано]":output,12,TEXT);
            view.setTextIsSelectable(true);
            body.addView(view);
        }
    }
    private void pair(){
        server=serverInput.getText().toString().trim();
        fingerprint=pinInput.getText().toString().trim();
        token=tokenInput.getText().toString().trim();
        try{
            GuestLabClient tmp=new GuestLabClient(server,fingerprint,token);
            lab=tmp;
            request("Гостевой Android",()->tmp.get("/v1/status"),true);
        }catch(Exception e){error("Не удалось настроить TLS",e);}
    }
    private interface Task {JSONObject run()throws Exception;}
    private void request(String title,Task action,boolean updateStatus){
        if(busy||lab==null)return;
        busy=true;render();
        worker.execute(()->{
            try{
                JSONObject result=action.run();
                JSONObject refreshed=null;
                if(updateStatus){
                    try{refreshed=lab.get("/v1/status");}
                    catch(Exception ignored){/* Keep the primary command result. */}
                }
                final JSONObject safeStatus=refreshed;
                runOnUiThread(()->{
                    if(isDestroyed()||isFinishing())return;
                    busy=false;outputTitle=title;output=result.toString();
                    if(safeStatus!=null){
                        status=safeStatus;
                        selected=status.optString("selected_package","");
                    }
                    render();
                });
            }catch(Exception e){
                runOnUiThread(()->{
                    if(isDestroyed()||isFinishing())return;
                    busy=false;error(title,e);
                    render();
                });
            }
        });
    }
    private void error(String title,Exception error){
        outputTitle="Ошибка: "+title;output=error.getMessage()==null?error.toString():error.getMessage();
        new AlertDialog.Builder(this).setTitle(title).setMessage(output)
            .setPositiveButton("Закрыть",null).show();
    }
    private void refreshPackages(){
        if(busy||lab==null)return;
        busy=true;render();
        worker.execute(()->{
            try{
                JSONObject obj=lab.get("/v1/packages");
                JSONArray list=obj.optJSONArray("packages");
                final List<String> names=new ArrayList<>();
                if(list!=null)for(int i=0;i<list.length();i++)names.add(list.optString(i));
                runOnUiThread(()->{
                    if(isDestroyed()||isFinishing())return;
                    packages.clear();packages.addAll(names);busy=false;
                    outputTitle="Пакеты гостевой Android";
                    output="Найдено пользовательских пакетов: "+packages.size();render();
                });
            }catch(Exception e){runOnUiThread(()->{busy=false;error("Пакеты",e);render();});}
        });
    }
    private void choosePackage(){
        if(packages.isEmpty()){
            new AlertDialog.Builder(this).setTitle("Список пуст")
                .setMessage("Нажмите «Обновить список гостевых приложений», затем выберите пакет.")
                .setPositiveButton("Понятно",null).show();return;
        }
        new AlertDialog.Builder(this).setTitle("Выбрать анализируемое приложение")
            .setItems(packages.toArray(new String[0]),(d,index)->{
                try{
                    JSONObject p=new JSONObject().put("package",packages.get(index));
                    request("Выбор приложения",()->lab.post("/v1/select",p),true);
                }catch(Exception e){error("Выбор",e);}
            }).setNegativeButton("Отмена",null).show();
    }
    private void network(boolean enabled){
        new AlertDialog.Builder(this).setTitle(enabled?"Включить сеть гостя?":"Отключить сеть гостя?")
            .setMessage("Это только Wi-Fi/мобильные данные гостевой Android. "+
                "Доступ через виртуальный NAT или интерфейсы хоста может сохраниться. "+
                "Для вредоносного ПО обязательно дополнительно блокируйте выход "+
                "в сеть на хостовой лаборатории.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton(enabled?"Включить":"Отключить",(d,w)->{
                try{
                    JSONObject payload=new JSONObject().put("allow",enabled);
                    request("Состояние гостевой сети",()->lab.post("/v1/network",payload),true);
                }catch(Exception e){error("Гостевая сеть",e);}
            }).show();
    }

    private void confirmImport(){
        new AlertDialog.Builder(this).setTitle("Загрузить APK в отдельную лабораторию?")
            .setMessage("Выбранный APK будет передан на указанный вами лабораторный компьютер "+
                "по HTTPS с проверкой сертификата и установлен ТОЛЬКО в его гостевой Android. "+
                "Это отправка байтов за пределы телефона. Не используйте неизвестный или публичный сервер.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Выбрать APK",(d,w)->{
                Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivityForResult(intent,PICK_APK);
            }).show();
    }
    private void confirmDump(){
        new AlertDialog.Builder(this).setTitle("Создать дамп памяти выбранного PID?")
            .setMessage("HPROF может содержать пароль, токен доступа, сообщения и другие секреты "+
                "исследуемого приложения. Дамп остаётся в лаборатории и по вашему выбору "+
                "сохраняется в выбранный файл на телефоне. Не пересылайте его третьим лицам.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Создать",(d,w)->request("Гостевой HPROF",()->{
                JSONObject result=lab.post("/v1/heap",new JSONObject());
                heapId=result.optString("artifact_id","");
                heapHash=result.optString("sha256","");
                heapName=result.optString("file_name","aster-heap.hprof");
                return result;
            },false)).show();
    }
    private void debugCommand(String cmd,String target){
        try{
            JSONObject data=new JSONObject().put("command",cmd).put("target",target);
            request("JDWP "+cmd,()->lab.post("/v1/debug/command",data),false);
        }catch(Exception e){error("JDWP",e);}
    }
    private void breakpoint(String mode){
        EditText input=input("com.example.Foo:123","",false);
        new AlertDialog.Builder(this).setTitle(mode.equals("break")?"JDWP breakpoint":"JDWP clear")
            .setMessage("Введите имя Java-класса и номер строки: пакет.Класс:строка")
            .setView(input).setNegativeButton("Отмена",null)
            .setPositiveButton("Отправить",(d,w)->debugCommand(mode,input.getText().toString().trim()))
            .show();
    }
    private void saveDump(){
        if(heapId.isEmpty())return;
        Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_TITLE,heapName);
        startActivityForResult(intent,SAVE_HEAP);
    }
    @Override protected void onActivityResult(int code,int result,Intent data){
        super.onActivityResult(code,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();
        if(code==SAVE_HEAP){
            if(busy||heapId.isEmpty())return;
            busy=true;render();
            final String id=heapId,hash=heapHash;
            worker.execute(()->{
                try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){
                    if(out==null)throw new java.io.IOException("Нельзя создать выбранный файл");
                    String receipt=lab.download(id,out,hash);
                    runOnUiThread(()->{
                        if(isDestroyed()||isFinishing())return;
                        busy=false;outputTitle="HPROF сохранён";output=receipt;render();
                    });
                }catch(Exception e){
                    runOnUiThread(()->{busy=false;error("Сохранение дампа",e);render();});
                }
            });
        }else if(code==PICK_APK){
            if(busy)return;
            busy=true;render();
            worker.execute(()->{
                File stage=new File(getCacheDir(),"lab-import.apk");
                try(InputStream in=getContentResolver().openInputStream(uri);
                    OutputStream out=new FileOutputStream(stage,false)){
                    if(in==null)throw new java.io.IOException("APK не открылся");
                    byte[] buffer=new byte[65536];long size=0;int n;
                    while((n=in.read(buffer))!=-1){
                        size+=n;
                        if(size>96L*1024*1024)throw new java.io.IOException("APK больше 96 МиБ");
                        out.write(buffer,0,n);
                    }
                    if(size<4)throw new java.io.IOException("APK пустой");
                    JSONObject res=lab.uploadApk(stage);
                    runOnUiThread(()->{
                        if(isDestroyed()||isFinishing())return;
                        busy=false;outputTitle="Установка в гостевую Android";
                        output=res.toString()+"\nОбновите список гостевых пакетов.";
                        render();
                    });
                }catch(Exception ex){
                    runOnUiThread(()->{busy=false;error("Гостевая установка",ex);render();});
                }finally{stage.delete();}
            });
        }
    }
    @Override protected void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
