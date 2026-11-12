package dev.aster.guard;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Explicit-user-choice APK editor. Does not remove developer license/payment
 * checks and never claims source-equivalent 32->64 ELF transformation.
 */
public final class ApkWorkshopActivity extends Activity {
    private static final int PICK_SO=6074,SAVE_APK=6075;
    private static final int BG=0xff0f1523,TXT=0xffedf6fa,MINT=0xff8cecd4,
        MUTED=0xffa4b8c8,AMBER=0xffffca82;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private LinearLayout body,root;
    private EditText keyInput,minInput,targetInput,nameInput;
    private File original,signed,replacementSo;
    private String keyName="mykey",asset="",output="Пока операций нет",label="";
    private String libraryAbi="",libraryName="",abiSummary="Ожидание анализа ELF";
    private ApkPatchSigner.ManifestInfo manifest;
    private int mode=ApkPatchSigner.REBUILD;
    private boolean busy;
    private int dp(int size){return Math.round(size*getResources().getDisplayMetrics().density);}
    @Override public void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        String source=getIntent().getStringExtra("archivePath");
        if(source==null){finish();return;}
        try{
            original=new File(source).getCanonicalFile();
            if(!original.isFile()||!original.getName().endsWith(".apk")||
                original.length()>ApkPatchSigner.MAX_APK ||
                !original.getParentFile().equals(getCacheDir().getCanonicalFile()))
                throw new IOException("Нужен APK из временного хранилища ASTER");
        }catch(Exception e){finish();return;}
        label=getIntent().getStringExtra("label");
        if(label==null||label.isEmpty())label="Выбранный APK";
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);root.setPadding(dp(12),dp(8),dp(12),dp(6));
        setContentView(root);
        LinearLayout nav=new LinearLayout(this);
        nav.setGravity(Gravity.CENTER_VERTICAL);
        nav.addView(button("‹ Назад",this::finish),new LinearLayout.LayoutParams(dp(96),dp(48)));
        nav.addView(text("ASTER · APK Editor",20,MINT));
        root.addView(nav);
        ScrollView sc=new ScrollView(this);
        body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(4),dp(6),dp(4),dp(24));
        sc.addView(body);
        root.addView(sc,new LinearLayout.LayoutParams(-1,0,1));
        render();
        worker.execute(()->{
            String abi;
            ApkPatchSigner.ManifestInfo info=null;
            try{info=ApkPatchSigner.manifest(original);abi=NativeAbiInspector.report(original);}
            catch(Exception e){abi="Ошибка чтения APK: "+e.getMessage();}
            final String result=abi;
            final ApkPatchSigner.ManifestInfo mi=info;
            runOnUiThread(()->{
                if(isFinishing()||isDestroyed())return;
                manifest=mi;abiSummary=result;render();
            });
        });
    }
    private TextView text(String value,int size,int color){
        TextView t=new TextView(this);t.setText(value);t.setTextColor(color);t.setTextSize(size);
        t.setPadding(dp(6),dp(7),dp(6),dp(7));return t;
    }
    private void line(String value,int size,int color){body.addView(text(value,size,color));}
    private Button button(String value,Runnable action){
        Button b=new Button(this);b.setAllCaps(false);b.setText(value);b.setTextSize(12);
        b.setOnClickListener(v->action.run());return b;
    }
    private EditText input(String hint,String initial){
        EditText e=new EditText(this);e.setTextColor(TXT);e.setHintTextColor(MUTED);
        e.setTextSize(14);e.setSingleLine(true);e.setHint(hint);
        e.setText(initial);body.addView(e);return e;
    }
    private void section(String title){line(title,17,MINT);}
    private void render(){
        if(body==null||isFinishing()||isDestroyed())return;
        String minText=minInput==null?"":minInput.getText().toString();
        String targetText=targetInput==null?"":targetInput.getText().toString();
        if(keyInput!=null)keyName=keyInput.getText().toString().trim();
        if(nameInput!=null)libraryName=nameInput.getText().toString().trim();
        body.removeAllViews();
        line(label,19,TXT);
        line("Работайте только со своими APK или приложениями, которые разрешено изменять. "+
            "Ключ издателя ASTER не затрагивается. Переподписанный APK обычно нельзя установить "+
            "поверх оригинального приложения.",13,AMBER);
        if(manifest!=null){
            line("Пакет: "+manifest.packageName+"\nminSdk "+manifest.minSdk+
                " · targetSdk "+manifest.targetSdk+
                " · телефон API "+android.os.Build.VERSION.SDK_INT,13,TXT);
            InstallAdvisor.Advice advice=InstallAdvisor.preflight(
                android.os.Build.VERSION.SDK_INT,manifest.minSdk,manifest.targetSdk);
            line(advice.summary+"\n"+advice.remedy,12,AMBER);
        }
        section("1. Собственный ключ");
        keyInput=input("Имя ключа (например mykey)",keyName);
        body.addView(button("Создать собственный RSA-ключ подписи",()->{
            keyName=keyInput.getText().toString().trim();
            task("Создание ключа",()->ApkPatchSigner.createKey(keyName));
        }));
        body.addView(button("Показать SHA-256 сертификата",()->{
            keyName=keyInput.getText().toString().trim();
            task("Сертификат",()->ApkPatchSigner.certificateSha256(keyName));
        }));
        line("Приватный ключ хранится в Android Keystore. После удаления приложения "+
            "он может стать недоступным; ASTER не восстанавливает исходную подпись автора.",12,MUTED);
        section("2. Манифест Android");
        minInput=input("Изменить minSdk (пусто = не менять)",minText);
        targetInput=input("Изменить targetSdk (пусто = не менять)",targetText);
        line("minSdk — лишь декларация. Понижение не добавляет Android API или "+
            "новые системные библиотеки. Для блокировки устаревшего targetSdk "+
            "лучше использовать подтверждённый параметр Shizuku.",12,AMBER);
        section("3. Действие с APK");
        body.addView(button((mode==0?"✓ ":"")+"Пересобрать / подписать APK",()->{mode=0;render();}));
        body.addView(button((mode==1?"✓ ":"")+"Выключить обнаруженные флаги аналитики в assets JSON",
            ()->{mode=1;render();}));
        body.addView(button((mode==2?"✓ ":"")+"Удалить выбранный assets/ файл",this::selectAsset));
        if(mode==2)line("Выбрано: "+asset,12,AMBER);
        body.addView(button((mode==3?"✓ ":"")+"Добавить/заменить ГОТОВУЮ .so нужной архитектуры",
            this::pickNative));
        if(mode==3){
            line(replacementSo==null?"Файл .so не выбран":
                "Библиотека: "+replacementSo.getName()+" · ELF ABI "+libraryAbi,13,TXT);
            nameInput=input("Имя библиотеки, например libfoo.so",libraryName);
            line("Файл должен быть уже скомпилирован под целевую ABI. "+
                "Нельзя автоматически сделать из ARM32 рабочий ARM64 путём переименования.",12,AMBER);
        }
        section("ABI и нативные библиотеки");
        line(abiSummary,12,MUTED);
        section("4. Подписать и проверить");
        if(busy)line("Выполняется операция…",13,MINT);
        else body.addView(button("Пересобрать → выровнять .so → подписать → проверить",
            this::confirmBuild));
        if(signed!=null&&signed.isFile()){
            line("Новый подписанный APK · "+signed.length()+" байт",13,MINT);
            body.addView(button("Сохранить APK через проводник",this::save));
            body.addView(button("Установить новый APK через Shizuku",()->confirmInstall(signed)));
        }
        section("5. Установка и диагностика");
        body.addView(button("Установить исходный APK через Shizuku",()->confirmInstall(original)));
        line("Подпись, split APK, ABI, защита Play Protect и ограничение minSdk "+
            "могут препятствовать установке. Обход minSdk параметром ADB не предусмотрен.",12,AMBER);
        section("Результат");line(output,12,TXT);
    }
    private interface Job{String run()throws Exception;}
    private void task(String title,Job job){
        if(busy)return;
        busy=true;render();
        worker.execute(()->{
            String answer;
            try{answer=job.run();}
            catch(Exception e){answer=e.getClass().getSimpleName()+": "+e.getMessage();}
            final String value=answer;
            runOnUiThread(()->{
                if(isDestroyed()||isFinishing())return;
                busy=false;output=title+": "+value;render();
            });
        });
    }
    private void selectAsset(){
        task("Список assets",()->{
            String[] found=ApkPatchSigner.assets(original);
            runOnUiThread(()->{
                if(found.length==0){notice("В APK нет подходящих файлов assets/");return;}
                new AlertDialog.Builder(this).setTitle("Какой файл удалить?")
                    .setItems(found,(d,which)->{asset=found[which];mode=2;render();})
                    .setNegativeButton("Отмена",null).show();
            });
            return "Найдено "+found.length+" файлов";
        });
    }
    private void pickNative(){
        mode=ApkPatchSigner.IMPORT_NATIVE_SO;render();
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("*/*");
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivityForResult(i,PICK_SO);
    }
    private void confirmBuild(){
        final ApkPatchSigner.Plan plan=new ApkPatchSigner.Plan();
        final String key=keyInput.getText().toString().trim();
        String min=minInput.getText().toString().trim(),target=targetInput.getText().toString().trim();
        try{
            plan.minSdk=min.isEmpty()?-1:Integer.parseInt(min);
            plan.targetSdk=target.isEmpty()?-1:Integer.parseInt(target);
        }catch(NumberFormatException e){notice("Укажите целое число SDK");return;}
        plan.mode=mode;plan.removeAsset=asset;plan.replacementSo=replacementSo;
        if(mode==ApkPatchSigner.IMPORT_NATIVE_SO){
            libraryName=nameInput==null?"":nameInput.getText().toString().trim();
            plan.replacementSoTarget="lib/"+libraryAbi+"/"+libraryName;
        }
        new AlertDialog.Builder(this).setTitle("Пересобрать и переподписать?")
            .setMessage("Подпись автора заменится вашим собственным сертификатом. "+
                "Установить как обновление поверх исходной версии обычно не получится. "+
                "Пересборка не гарантирует запуск на несовместимой версии Android.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Пересобрать",(d,w)->task("APK Editor",()->{
                File target=new File(getCacheDir(),"aster-patched-"+System.nanoTime()+".apk");
                ApkPatchSigner.Result result=ApkPatchSigner.rebuildAndSign(original,target,key,plan);
                signed=result.file;
                return "Подпись проверена: "+result.verified+
                    "\nSHA-256: "+result.hash+
                    "\nСертификат: "+result.certificateHash+
                    "\nminSdk: "+result.oldMinSdk+" → "+result.newMinSdk+
                    "\ntargetSdk: "+result.oldTargetSdk+" → "+result.newTargetSdk+
                    "\nФлагов JSON: "+result.changedConfigurations+
                    ", удалено assets: "+result.removedAssets;
            })).show();
    }
    private void confirmInstall(File file){
        if(!ShizukuBridge.authorized()){notice("Нужно запустить Shizuku и дать разрешение ASTER");return;}
        final ApkPatchSigner.ManifestInfo m;
        try{m=ApkPatchSigner.manifest(file);}
        catch(Exception e){notice("Не удалось прочитать манифест APK: "+e);return;}
        final InstallAdvisor.Advice check=InstallAdvisor.preflight(
            android.os.Build.VERSION.SDK_INT,m.minSdk,m.targetSdk);
        boolean bypass=check.legacyTargetBypass;
        new AlertDialog.Builder(this).setTitle("Установка через Shizuku")
            .setMessage("Пакет: "+m.packageName+"\n"+check.summary+"\n"+check.remedy+
                "\n\nВыбранный файл будет передан службе Shizuku (ADB/shell). "+
                (bypass?"Будет применён --bypass-low-target-sdk-block. ":"")+
                "Установка может повлиять на безопасность устройства. Для подозрительного ПО используйте гостевую лабораторию.")
            .setNegativeButton("Отмена",null)
            .setPositiveButton("Установить",(d,w)->task("Shizuku APK install",()->{
                String response=ShizukuBridge.installSelectedApk(
                    getApplicationContext(),file,bypass,false);
                InstallAdvisor.Advice advice=InstallAdvisor.failure(response);
                return response+"\n\n"+advice.summary+"\n"+advice.remedy;
            })).show();
    }
    private void save(){
        Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/vnd.android.package-archive");
        i.putExtra(Intent.EXTRA_TITLE,"ASTER-patched.apk");
        startActivityForResult(i,SAVE_APK);
    }
    @Override protected void onActivityResult(int request,int code,Intent data){
        super.onActivityResult(request,code,data);
        if(code!=RESULT_OK||data==null||data.getData()==null)return;
        Uri uri=data.getData();
        if(request==PICK_SO){
            task("Проверка .so",()->{
                File nativeFile=new File(getCacheDir(),"aster-candidate-"+System.nanoTime()+".so");
                try(InputStream in=getContentResolver().openInputStream(uri);
                    OutputStream out=new FileOutputStream(nativeFile)){
                    if(in==null)throw new IOException("Файл не открылся");
                    byte[] buf=new byte[32768];int n;long total=0;
                    while((n=in.read(buf))!=-1){
                        total+=n;
                        if(total>64L*1024*1024)throw new IOException("Максимум 64 МиБ");
                        out.write(buf,0,n);
                    }
                }catch(Exception e){nativeFile.delete();throw e;}
                NativeAbiInspector.Elf elf=NativeAbiInspector.inspect(nativeFile);
                if(!elf.valid){nativeFile.delete();throw new IOException("Это не поддерживаемый ELF .so");}
                replacementSo=nativeFile;
                libraryAbi=elf.abi;
                libraryName="libcustom.so";
                return "Получено: "+elf.description()+"\nВыберите имя и запустите пересборку.";
            });
        }else if(request==SAVE_APK&&signed!=null){
            final File candidate=signed;
            task("Сохранение APK",()->{
                try(InputStream in=new FileInputStream(candidate);
                    OutputStream out=getContentResolver().openOutputStream(uri,"w")){
                    if(out==null)throw new IOException("Не удаётся создать файл");
                    byte[] b=new byte[32768];int n;
                    while((n=in.read(b))!=-1)out.write(b,0,n);
                }
                return "Готово: APK сохранён в выбранную папку";
            });
        }
    }
    private void notice(String message){
        new AlertDialog.Builder(this).setMessage(message)
            .setPositiveButton("Закрыть",null).show();
    }
    @Override protected void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
