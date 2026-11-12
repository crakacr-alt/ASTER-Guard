package dev.aster.guard;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.database.Cursor;
import android.provider.OpenableColumns;
import java.io.ByteArrayOutputStream;
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
    private static final int PICK_APK=5041,SAVE_HEAP=5042,PICK_NATIVE_SOURCE=5043,SAVE_NATIVE_SO=5044,PICK_SANDBOX_APK=5045,SAVE_SANDBOX_REPORT=5046;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private GuestLabClient lab;
    private LinearLayout root,body;
    private EditText serverInput,pinInput,tokenInput;
    private String server="",fingerprint="",token="";
    private JSONObject status;
    private final List<String> packages=new ArrayList<>();
    private String selected="",output="",outputTitle="Отчёт",heapId="",heapHash="",heapName="";
    private JSONArray nativeOutputs=new JSONArray();
    private String[] compileAbis={"armeabi-v7a","arm64-v8a"};
    private String compileLibrary="libastercustom.so";
    private int compileApi=24;
    private String nativeArtifactId="",nativeArtifactSha="",nativeArtifactName="";
    private JSONObject sandboxState=new JSONObject();
    private String sandboxStagedId="",sandboxReportId="",sandboxReportFormat="";
    private final android.os.Handler sandboxHandler=new android.os.Handler(android.os.Looper.getMainLooper());
    private boolean sandboxPolling;
    private final Runnable sandboxTick=new Runnable(){
        @Override public void run(){
            if(!sandboxPolling||lab==null||isDestroyed()||isFinishing())return;
            if(!busy){
                worker.execute(()->{
                    try{
                        JSONObject next=lab.get("/v1/sandbox/status");
                        runOnUiThread(()->{
                            if(!sandboxPolling||isDestroyed()||isFinishing())return;
                            String previous=sandboxState.optString("status","");
                            String current=next.optString("status","");
                            sandboxState=next;
                            if(!current.equals(previous)||"running".equals(current)||
                               "restoring".equals(current))render();
                        });
                    }catch(Exception ignored){}
                });
            }
            sandboxHandler.postDelayed(this,3000);
        }
    };
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
    @Override protected void onResume(){
        super.onResume();
        sandboxPolling=true;
        sandboxHandler.removeCallbacks(sandboxTick);
        sandboxHandler.postDelayed(sandboxTick,1500);
    }
    @Override protected void onPause(){
        sandboxPolling=false;
        sandboxHandler.removeCallbacks(sandboxTick);
        super.onPause();
    }
    private void render(){
        if(isDestroyed()||isFinishing())return;
        body.removeAllViews();
        line("Гостевая Android 7+ · отдельная лаборатория",19,TEXT);
        line("Весь пульт управления расположен в ASTER. Сам Android Emulator с root работает на вашем отдельном ПК/сервере, "+
             "а НЕ внутри этого APK или основного телефона. Не запускайте подозрительный APK на основной ОС.",13,AMBER);
        heading("Режим лаборатории");
        body.addView(button("Локально на этом телефоне · без сервера",()->{
            startActivity(new Intent(this,FileScanActivity.class));
        }));
        line("Локальный режим выполняет статическую проверку выбранных файлов, "+
            "DEX-кода и трекеров без установки APK. Он работает без интернета, "+
            "но НЕ создаёт гостевую Android-систему и НЕ запускает вирусы.",12,MUTED);
        if(lab==null){
            body.addView(button("Настроить собственный ПК / VPS · гайд и автоустановка",
                this::serverSetupGuide));
            heading("Подключиться к своему серверу с Android-гостем");
            line("Требуется HTTPS-адрес частного лабораторного моста, SHA-256 его сертификата и секретный токен. "+
                 "Проверьте отпечаток вручную. Не открывайте мост в публичный интернет.",12,MUTED);
            serverInput=input("https://192.168.x.x:8742",server.isEmpty()?"":server,false);
            pinInput=input("SHA-256 сертификата · 64 символа",fingerprint,false);
            tokenInput=input("Токен сопряжения",token,true);
            body.addView(serverInput);body.addView(pinInput);body.addView(tokenInput);
            body.addView(button("Подключиться по HTTPS",this::pair));
            line("Укажите частный IP вашего ПК/VPS, например https://192.168.1.100:8742 "+
                 "или адрес Tailscale 100.x.x.x. Адрес 127.0.0.1 на телефоне "+
                 "указывает на сам телефон, а НЕ на сервер.",12,AMBER);
            line("На собственном Linux x86_64 ПК сервер можно подготовить скриптом "+
                 "из репозитория ASTER. Нужен KVM; обычный VPS без nested virtualization "+
                 "может не поддерживать Android Emulator.",12,MUTED);
            return;
        }
        line(busy?"Выполняется команда в отдельном потоке…":"Мост сопряжён · TLS-пин проверяется при каждом запросе",13,busy?AMBER:MINT);
        body.addView(button("Проверить статус гостевой Android",()->request("Статус Android",()->lab.get("/v1/status"),true)));
        body.addView(button("Отключить лабораторию",()->{
            lab=null;status=null;packages.clear();selected="";heapId="";token="";nativeOutputs=new JSONArray();
            sandboxState=new JSONObject();sandboxStagedId="";render();
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
        heading("Sandbox Analyzer · автоматический анализ APK");
        line("Последовательность: чистый снимок гостя → установка APK → "+
            "наблюдение → сравнение изменений → отчёт JSON/HTML → восстановление снимка. "+
            "Все действия выполняются на отдельном root-эмуляторе, не на телефоне.",13,MUTED);
        line("Запуск блокируется, пока администратор лаборатории не подтвердит "+
            "проверенную блокировку сетевого выхода НА ХОСТЕ. ASTER не умеет "+
            "самостоятельно проверять её и не гарантирует полную изоляцию.",12,AMBER);
        body.addView(button("1. Выбрать APK для песочницы",this::pickSandboxApk));
        if(!sandboxStagedId.isEmpty()){
            line("Файл подготовлен в закрытом хранилище лаборатории. "+
                "Он ещё не установлен и не запускался.",12,MINT);
            body.addView(button("2. Запустить полный цикл анализа",this::chooseSandboxDuration));
        }
        body.addView(button("Обновить состояние Sandbox Analyzer",()->
            request("Sandbox статус",()->lab.get("/v1/sandbox/status"),false)));
        String sandboxStatus=sandboxState.optString("status","idle");
        line("Статус: "+sandboxStatus+" · "+
            sandboxState.optString("phase","")+
            " · "+sandboxState.optInt("percent")+"%",13,MINT);
        if("running".equals(sandboxStatus)||"queued".equals(sandboxStatus)||
            "restoring".equals(sandboxStatus))
            body.addView(button("Остановить анализ и восстановить снимок",()->
                request("Sandbox отмена",()->lab.post("/v1/sandbox/cancel",new JSONObject()),false)));
        JSONObject counts=sandboxState.optJSONObject("summary");
        if(counts!=null){
            line("Пакет: "+counts.optString("package","")+
                "\nСозданных файлов: "+counts.optInt("created_files")+
                " · изменённых: "+counts.optInt("changed_files")+
                " · удалённых: "+counts.optInt("removed_files")+
                "\nНовых пакетов: "+counts.optInt("new_packages")+
                " · изменённых настроек: "+counts.optInt("changed_settings")+
                "\nВосстановление снимка подтверждено: "+
                counts.optBoolean("restored"),13,TEXT);
            line(counts.optString("coverage_warning",
                "Наблюдение ограничено. Не все операции попадают в журнал."),12,AMBER);
        }
        JSONArray timeline=sandboxState.optJSONArray("events");
        if(timeline!=null&&timeline.length()>0){
            line("Последние события анализа:",13,MINT);
            for(int i=Math.max(0,timeline.length()-10);i<timeline.length();i++){
                JSONObject step=timeline.optJSONObject(i);
                if(step!=null)line("• "+step.optString("phase","")+
                    ": "+step.optString("detail",""),12,MUTED);
            }
        }
        if(!sandboxState.optString("report_json_artifact","").isEmpty()){
            body.addView(button("Сохранить итоговый отчёт JSON",()->saveSandboxReport("json")));
            body.addView(button("Сохранить итоговый отчёт HTML",()->saveSandboxReport("html")));
        }
        heading("Сборка C/C++ → нативные .so (Android NDK)");
        line("Соберите собственный исходник для ARM32/ARM64/x86/x86_64. "+
            "Компиляция идёт на подключённом лабораторном ПК в offline-песочнице bubblewrap. "+
            "На телефоне исходный код не выполняется; собранный ELF не запускается на хосте.",12,MUTED);
        body.addView(button("Проверить готовность NDK и песочницы",()->
            request("NDK / sandbox",()->lab.get("/v1/native/status"),false)));
        body.addView(button("Выбрать .c/.cpp и собрать библиотеку",this::chooseNativeOptions));
        if(nativeOutputs.length()>0)
            body.addView(button("Сохранить собранную .so",this::chooseNativeArtifact));
        line("Сохранённую .so затем выберите в ASTER → Проверка файла → APK Editor → "+
            "«Добавить/заменить .so». Автоматического перевода готовых ARM32-бинарников "+
            "в ARM64 нет: нужен исходный C/C++ код.",12,AMBER);
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
    private void serverSetupGuide(){
        String commands="git clone https://github.com/crakacr-alt/ASTER-Guard.git\n"+
            "cd ASTER-Guard\n"+
            "sudo bash lab/auto_setup_server.sh";
        String message="СОБСТВЕННАЯ ANDROID-ЛАБОРАТОРИЯ\n\n"+
            "Нужен отдельный Linux x86_64 ПК / VPS с доступным /dev/kvm. "+
            "На обычном VPS без KVM Android Emulator может не работать.\n\n"+
            "1. Выполните на своём ПК:\n\n"+commands+"\n\n"+
            "2. По умолчанию мост слушает только 127.0.0.1 НА ПК. "+
            "Для подключения телефона повторно запустите скрипт с фактическим "+
            "приватным адресом, например:\n\n"+
            "sudo bash lab/auto_setup_server.sh --bind 192.168.1.100\n\n"+
            "3. Для Tailscale укажите приватный IP 100.x.x.x. "+
            "Не открывайте порт 8742 в публичный интернет.\n\n"+
            "4. Скрипт выдаст HTTPS-адрес, SHA-256 сертификата и токен. "+
            "Вставьте эти три значения в форму подключения ASTER.\n\n"+
            "5. Для запуска неизвестного APK настройте и отдельно ПРОВЕРЬТЕ "+
            "сетевую изоляцию лабораторного хоста. Установщик не считает "+
            "изолированность автоматически доказанной.\n\n"+
            "Статус: sudo systemctl status aster-guest aster-bridge\n\n"+
            "Полный гайд: github.com/crakacr-alt/ASTER-Guard/blob/main/docs/HOST_AUTOINSTALL.md";
        TextView info=text(message,13,TEXT);
        info.setTextIsSelectable(true);
        ScrollView scroll=new ScrollView(this);scroll.addView(info);
        new AlertDialog.Builder(this).setTitle("Настройка Android Lab на ПК/VPS")
            .setView(scroll).setNegativeButton("Закрыть",null)
            .setPositiveButton("Скопировать команды",(d,w)->{
                ClipboardManager cb=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
                if(cb!=null)cb.setPrimaryClip(ClipData.newPlainText("ASTER Lab setup",commands));
            }).show();
    }
    private void pair(){
        server=serverInput.getText().toString().trim();
        fingerprint=pinInput.getText().toString().trim();
        token=tokenInput.getText().toString().trim();
        try{
            GuestLabClient tmp=new GuestLabClient(server,fingerprint,token);
            lab=tmp;
            request("NDK / sandbox",()->tmp.get("/v1/native/status"),false);
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
                    if("Sandbox статус".equals(title)||
                       "Sandbox отмена".equals(title)||
                       "Sandbox запуск".equals(title))sandboxState=result;
                    if("Sandbox подготовлен".equals(title))
                        sandboxStagedId=result.optString("artifact_id","");
                    if("NDK сборка".equals(title)){
                        JSONArray created=result.optJSONArray("outputs");
                        nativeOutputs=created==null?new JSONArray():created;
                    }
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
    private void pickSandboxApk(){
        if(lab==null)return;
        new AlertDialog.Builder(this).setTitle("Подготовить APK для исследования?")
            .setMessage("Выбранный файл будет передан по защищённому каналу на "+
                "ваш лабораторный компьютер. Этот шаг НЕ устанавливает APK и "+
                "НЕ запускает его. Не соединяйтесь с чужими лабораторными серверами.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Выбрать APK",(dialog,which)->{
                Intent pick=new Intent(Intent.ACTION_OPEN_DOCUMENT);
                pick.addCategory(Intent.CATEGORY_OPENABLE);
                pick.setType("*/*");
                pick.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivityForResult(pick,PICK_SANDBOX_APK);
            }).show();
    }
    private void stageSandboxApk(Uri uri){
        if(lab==null||busy)return;
        busy=true;render();
        worker.execute(()->{
            File tmp=new File(getCacheDir(),"aster-sandbox-selected.apk");
            try(InputStream in=getContentResolver().openInputStream(uri);
                OutputStream out=new java.io.FileOutputStream(tmp,false)){
                if(in==null)throw new java.io.IOException("Не удалось прочитать APK");
                byte[] buffer=new byte[65536];long size=0;int len;
                while((len=in.read(buffer))!=-1){
                    size+=len;
                    if(size>96L*1024*1024)
                        throw new java.io.IOException("Лимит APK 96 МиБ");
                    out.write(buffer,0,len);
                }
                if(size<4)throw new java.io.IOException("Пустой APK");
                JSONObject result=lab.stageSandboxApk(tmp);
                runOnUiThread(()->{
                    if(isDestroyed()||isFinishing())return;
                    sandboxStagedId=result.optString("artifact_id","");
                    busy=false;outputTitle="Sandbox: APK подготовлен";
                    output=result.toString();
                    render();
                });
            }catch(Exception e){
                runOnUiThread(()->{busy=false;error("Подготовка Sandbox APK",e);render();});
            }finally{tmp.delete();}
        });
    }
    private void chooseSandboxDuration(){
        if(sandboxStagedId.isEmpty()||lab==null)return;
        final int[] duration={15,30,60,120};
        new AlertDialog.Builder(this).setTitle("Время наблюдения")
            .setItems(new String[]{"15 секунд","30 секунд","60 секунд","120 секунд"},
                (d,index)->confirmSandboxStart(duration[index]))
            .setNegativeButton("Отмена",null).show();
    }
    private void confirmSandboxStart(int seconds){
        new AlertDialog.Builder(this).setTitle("Запустить подозрительный APK в гостевой Android?")
            .setMessage("Только отдельный лабораторный компьютер! "+
                "Настройки Wi-Fi гостя НЕ гарантируют изоляцию вируса. "+
                "До запуска необходимо самостоятельно настроить и проверить "+
                "блокировку исходящих соединений на лабораторном хосте. "+
                "Для восстановления ASTER сохранит системный снимок. "+
                "Если снимок создать не удастся, APK не будет установлен. "+
                "Согласны запустить выбранный APK в лаборатории?")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Запустить анализ",(d,w)->{
                try{
                    JSONObject payload=new JSONObject()
                        .put("artifact_id",sandboxStagedId)
                        .put("duration_seconds",seconds)
                        .put("acknowledge_lab_risk",true);
                    request("Sandbox запуск",()->lab.post("/v1/sandbox/begin",payload),false);
                }catch(Exception e){error("Запуск анализа",e);}
            }).show();
    }
    private void saveSandboxReport(String format){
        if(lab==null||!("json".equals(format)||"html".equals(format)))return;
        String id=sandboxState.optString("report_"+format+"_artifact","");
        if(!id.matches("[0-9a-f]{32}"))return;
        sandboxReportId=id;sandboxReportFormat=format;
        Intent save=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("html".equals(format)?"text/html":"application/json");
        save.putExtra(Intent.EXTRA_TITLE,"ASTER-sandbox-report."+format);
        startActivityForResult(save,SAVE_SANDBOX_REPORT);
    }
    private void chooseNativeOptions(){
        final String[] labels={
            "ARM 32 + ARM 64 (две .so)","Только ARM32 · armeabi-v7a",
            "Только ARM64 · arm64-v8a",
            "Только x86 (32-bit)","Только x86_64 (64-bit)",
            "Все четыре ABI"
        };
        new AlertDialog.Builder(this).setTitle("Целевые архитектуры")
            .setItems(labels,(dialog,index)->configureNative(index))
            .setNegativeButton("Отмена",null).show();
    }
    private void configureNative(int selectedIndex){
        final String[][] options={
            {"armeabi-v7a","arm64-v8a"},
            {"armeabi-v7a"},{"arm64-v8a"},{"x86"},{"x86_64"},
            {"armeabi-v7a","arm64-v8a","x86","x86_64"}
        };
        final String[] abis=options[selectedIndex];
        LinearLayout fields=new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        fields.setPadding(dp(18),dp(8),dp(18),dp(8));
        EditText library=input("libexample.so",compileLibrary,false);
        EditText level=input("API 24–35",Integer.toString(compileApi),false);
        level.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        fields.addView(text("Имя нативной библиотеки (.so)",13,MUTED));
        fields.addView(library);
        fields.addView(text("Минимальный Android API для C/C++",13,MUTED));
        fields.addView(level);
        new AlertDialog.Builder(this).setTitle("Сборка Android NDK")
            .setView(fields)
            .setMessage("После выбора файл исходного кода C/C++ будет отправлен ТОЛЬКО "+
                "на сопряжённый лабораторный ПК по HTTPS. "+
                "Без NDK и bubblewrap сборка не начнётся. "+
                "Результат будет отдельным ELF-файлом для выбранных ABI.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Выбрать исходник",(d,w)->{
                String lib=library.getText().toString().trim();
                int api;
                try{api=Integer.parseInt(level.getText().toString().trim());}
                catch(NumberFormatException exc){error("API",new Exception("Нужен номер API 24–35"));return;}
                if(api<24||api>35||!lib.matches("lib[A-Za-z0-9_]{1,48}\\.so")){
                    error("Параметры",new Exception("API 24–35, имя libexample.so"));return;
                }
                compileAbis=abis;compileLibrary=lib;compileApi=api;
                Intent picker=new Intent(Intent.ACTION_OPEN_DOCUMENT);
                picker.addCategory(Intent.CATEGORY_OPENABLE);
                picker.setType("*/*");
                picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivityForResult(picker,PICK_NATIVE_SOURCE);
            }).show();
    }
    private String sourceLanguage(Uri uri)throws Exception{
        String name="";
        try(Cursor c=getContentResolver().query(uri,
            new String[]{OpenableColumns.DISPLAY_NAME},null,null,null)){
            if(c!=null&&c.moveToFirst()){
                int col=c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if(col>=0)name=c.getString(col);
            }
        }
        if(name==null)name="";
        String lower=name.toLowerCase(java.util.Locale.ROOT);
        if(lower.endsWith(".cpp")||lower.endsWith(".cc")||lower.endsWith(".cxx"))return "cpp";
        if(lower.endsWith(".c"))return "c";
        throw new java.io.IOException("Выберите файл .c, .cpp, .cc или .cxx");
    }
    private void compileSelectedSource(Uri uri){
        if(busy||lab==null)return;
        final String language;
        try{language=sourceLanguage(uri);}
        catch(Exception e){error("C/C++",e);return;}
        final String[] abis=compileAbis.clone();
        final String library=compileLibrary;
        final int api=compileApi;
        request("NDK сборка",()->{
            byte[] source;
            try(InputStream in=getContentResolver().openInputStream(uri)){
                if(in==null)throw new java.io.IOException("Не удалось открыть исходник");
                ByteArrayOutputStream out=new ByteArrayOutputStream();
                byte[] buffer=new byte[8192];int n;
                while((n=in.read(buffer))!=-1){
                    if(out.size()+n>64*1024)
                        throw new java.io.IOException("Файл исходника превышает 64 КиБ");
                    out.write(buffer,0,n);
                }
                source=out.toByteArray();
            }
            return lab.buildNative(source,language,abis,api,library);
        },false);
    }
    private void chooseNativeArtifact(){
        if(nativeOutputs.length()==0)return;
        String[] choices=new String[nativeOutputs.length()];
        for(int i=0;i<nativeOutputs.length();i++){
            JSONObject item=nativeOutputs.optJSONObject(i);
            choices[i]=item==null?"Ошибка данных":
                item.optString("abi")+" · "+
                item.optString("name")+" · "+item.optInt("bytes")+" байт";
        }
        new AlertDialog.Builder(this).setTitle("Сохранить собранную библиотеку")
            .setItems(choices,(d,which)->{
                JSONObject item=nativeOutputs.optJSONObject(which);
                if(item==null)return;
                nativeArtifactId=item.optString("artifact_id");
                nativeArtifactSha=item.optString("sha256");
                nativeArtifactName=item.optString("name","libastercustom.so");
                if(!nativeArtifactId.matches("[0-9a-f]{32}"))return;
                Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/octet-stream");
                intent.putExtra(Intent.EXTRA_TITLE,nativeArtifactName);
                startActivityForResult(intent,SAVE_NATIVE_SO);
            }).setNegativeButton("Отмена",null).show();
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
        if(code==PICK_SANDBOX_APK){
            stageSandboxApk(uri);
        }else if(code==SAVE_SANDBOX_REPORT){
            if(lab==null||busy||sandboxReportId.isEmpty())return;
            busy=true;render();
            final String id=sandboxReportId;
            worker.execute(()->{
                try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){
                    if(out==null)throw new java.io.IOException("Нельзя создать файл отчёта");
                    String receipt=lab.download(id,out,"");
                    runOnUiThread(()->{
                        if(isDestroyed()||isFinishing())return;
                        busy=false;outputTitle="Sandbox отчёт сохранён";output=receipt;render();
                    });
                }catch(Exception e){
                    runOnUiThread(()->{busy=false;error("Сохранение отчёта",e);render();});
                }
            });
        }else if(code==PICK_NATIVE_SOURCE){
            compileSelectedSource(uri);
        }else if(code==SAVE_NATIVE_SO){
            if(busy||nativeArtifactId.isEmpty()||lab==null)return;
            busy=true;render();
            final String id=nativeArtifactId,hash=nativeArtifactSha;
            worker.execute(()->{
                try(OutputStream out=getContentResolver().openOutputStream(uri,"w")){
                    if(out==null)throw new java.io.IOException("Не удалось открыть место сохранения");
                    String receipt=lab.download(id,out,hash);
                    runOnUiThread(()->{
                        if(isDestroyed()||isFinishing())return;
                        busy=false;outputTitle="Нативная .so сохранена";
                        output=receipt+"\nТеперь импортируйте её в APK Editor.";
                        render();
                    });
                }catch(Exception e){
                    runOnUiThread(()->{
                        busy=false;error("Сохранение .so",e);render();
                    });
                }
            });
        }else if(code==SAVE_HEAP){
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
    @Override protected void onDestroy(){
        sandboxPolling=false;
        sandboxHandler.removeCallbacks(sandboxTick);
        worker.shutdownNow();
        super.onDestroy();
    }
}
