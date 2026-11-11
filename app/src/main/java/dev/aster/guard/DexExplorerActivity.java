package dev.aster.guard;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.text.Editable;
import android.text.TextWatcher;
import org.jf.dexlib2.iface.Method;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Real, searchable, read-only class → method → DEX instruction navigation. */
public final class DexExplorerActivity extends Activity {
    private static final int BG=0xff0f1523,SURFACE=0xff1a2534,TXT=0xffedf6fa,
        MUTED=0xffa4b8c8,MINT=0xff8cecd4;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final DexCodeReader reader=DexCodeReader.create();
    private final List<DexCodeReader.Item> classes=new ArrayList<>();
    private final List<Method> methods=new ArrayList<>();
    private LinearLayout root,listing,header;
    private EditText search;
    private TextView title,subtitle;
    private DexCodeReader.Item currentClass;
    private Method currentMethod;
    private String pkg="",label="",currentCode="";
    private int page=0;
    private boolean appOnly=true,loading=true;
    private String notes="";

    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
        pkg=getIntent().getStringExtra("packageName");
        if(pkg==null||pkg.isEmpty()){finish();return;}
        label=getIntent().getStringExtra("label");
        if(label==null||label.isEmpty())label=pkg;
        build();
        load();
    }
    private int dp(int v){return Math.round(v*getResources().getDisplayMetrics().density);}
    private TextView text(String s,int size,int color){
        TextView t=new TextView(this);t.setText(s);t.setTextColor(color);t.setTextSize(size);
        t.setPadding(dp(10),dp(8),dp(10),dp(8));return t;
    }
    private Button button(String s,Runnable action){
        Button b=new Button(this);b.setText(s);b.setTextSize(12);b.setAllCaps(false);
        b.setOnClickListener(v->action.run());return b;
    }
    private void build(){
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        root.setPadding(dp(8),dp(8),dp(8),0);
        setContentView(root);
        header=new LinearLayout(this);header.setOrientation(LinearLayout.VERTICAL);
        root.addView(header,new LinearLayout.LayoutParams(-1,-2));
        LinearLayout nav=new LinearLayout(this);nav.setGravity(Gravity.CENTER_VERTICAL);
        header.addView(nav);
        nav.addView(button("‹ Назад",()->onBackPressed()),new LinearLayout.LayoutParams(dp(105),dp(46)));
        TextView heading=text("DEX / Smali",21,MINT);
        heading.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        nav.addView(heading,new LinearLayout.LayoutParams(0,-2,1));
        nav.addView(button("Закрыть",this::finish),new LinearLayout.LayoutParams(dp(98),dp(46)));
        title=text(label,16,TXT);
        title.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
        header.addView(title);
        subtitle=text("Читаем DEX... ",12,MUTED);
        header.addView(subtitle);
        search=new EditText(this);
        search.setSingleLine(true);search.setTextSize(14);search.setTextColor(TXT);
        search.setHintTextColor(MUTED);search.setHint("Поиск класса...");
        header.addView(search,new LinearLayout.LayoutParams(-1,dp(52)));
        search.addTextChangedListener(new TextWatcher(){
            public void beforeTextChanged(CharSequence s,int start,int count,int after){}
            public void onTextChanged(CharSequence s,int start,int before,int count){
                if(page<2)renderList();
            }
            public void afterTextChanged(Editable e){}
        });
        ScrollView scroll=new ScrollView(this);
        listing=new LinearLayout(this);
        listing.setOrientation(LinearLayout.VERTICAL);
        listing.setPadding(dp(4),dp(5),dp(4),dp(18));
        scroll.addView(listing);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
    }
    private void load(){
        subtitle.setText("Индексируем классы APK и split APK (только по нажатию)...");
        worker.execute(()->{
            try{
                ApplicationInfo info=getPackageManager().getApplicationInfo(pkg,0);
                List<String> paths=new ArrayList<>();paths.add(info.sourceDir);
                if(info.splitSourceDirs!=null)java.util.Collections.addAll(paths,info.splitSourceDirs);
                DexCodeReader.Index idx=reader.index(paths.toArray(new String[0]),pkg);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed())return;
                    classes.clear();classes.addAll(idx.classes);
                    int own=0;String prefix="L"+pkg.replace('.','/')+"/";
                    for(DexCodeReader.Item c:classes)if(c.type.startsWith(prefix))own++;
                    appOnly=own>0;
                    notes="DEX: "+idx.dexFiles+" · классов: "+idx.classes.size()+
                        " · собственных: "+own;
                    if(!idx.skipped.isEmpty())notes+=" · пропущено: "+idx.skipped.size();
                    loading=false;renderList();
                });
            }catch(Exception e){
                runOnUiThread(()->{
                    loading=false;notes="Ошибка чтения: "+e.getMessage();
                    renderList();
                });
            }
        });
    }
    private void renderList(){
        if(listing==null||page==2)return;
        listing.removeAllViews();
        if(page==0){
            title.setText(label+" · Классы");
            subtitle.setText(notes+"\nНе исходный Java-код: DEX → инструкции (Smali-like)");
            search.setHint("Найти класс по имени...");
            listing.addView(button(appOnly?"Показать все библиотеки":"Только классы приложения",()->{
                appOnly=!appOnly;renderList();
            }),new LinearLayout.LayoutParams(-1,dp(46)));
            if(loading){
                ProgressBar progress=new ProgressBar(this);
                listing.addView(progress,new LinearLayout.LayoutParams(-1,dp(70)));
                return;
            }
            String query=search.getText().toString().toLowerCase(Locale.ROOT).trim();
            String prefix="L"+pkg.replace('.','/')+"/";
            int visible=0,matching=0;
            for(DexCodeReader.Item cls:classes){
                if(appOnly&&!cls.type.startsWith(prefix))continue;
                if(!cls.simple().toLowerCase(Locale.ROOT).contains(query))continue;
                matching++;
                if(visible++>=120)continue;
                listing.addView(entry(cls.simple()+"\n"+cls.entry,()->selectClass(cls)));
            }
            listing.addView(text("Найдено: "+matching+
                (matching>120?" · показаны первые 120, уточните поиск":"")+
                "\nДля просмотра методов нажмите на класс.",12,MUTED));
        }else{
            title.setText(currentClass==null?"Методы":"Методы · "+currentClass.simple());
            subtitle.setText("Выбери метод, чтобы посмотреть реальные операции DEX. Это не живой отладчик.");
            search.setHint("Найти метод...");
            String q=search.getText().toString().toLowerCase(Locale.ROOT);
            int count=0;
            for(Method m:methods){
                final String signature=DexCodeReader.methodName(m);
                if(!signature.toLowerCase(Locale.ROOT).contains(q))continue;
                if(count++>=120)continue;
                listing.addView(entry(signature,()->selectMethod(m)));
            }
            listing.addView(text("Найдено методов: "+count+
                (count>120?" · первые 120":""),12,MUTED));
        }
    }
    private View entry(String s,Runnable action){
        TextView item=text(s,14,TXT);
        item.setBackgroundColor(SURFACE);
        item.setPadding(dp(15),dp(12),dp(12),dp(12));
        LinearLayout wrap=new LinearLayout(this);wrap.setPadding(0,0,0,dp(6));
        wrap.addView(item,new LinearLayout.LayoutParams(-1,-2));
        wrap.setOnClickListener(v->{
            ((InputMethodManager)getSystemService(INPUT_METHOD_SERVICE))
                .hideSoftInputFromWindow(search.getWindowToken(),0);
            action.run();
        });
        return wrap;
    }
    private void selectClass(DexCodeReader.Item item){
        currentClass=item;methods.clear();page=1;
        search.setText("");
        listing.removeAllViews();listing.addView(text("Читаем методы выбранного класса…",14,MUTED));
        worker.execute(()->{
            try{
                List<Method> found=reader.methods(item);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed()||currentClass!=item)return;
                    methods.clear();methods.addAll(found);renderList();
                });
            }catch(Exception e){runOnUiThread(()->showError(e));}
        });
    }
    private void selectMethod(Method m){
        currentMethod=m;page=2;
        title.setText(DexCodeReader.methodName(m));
        subtitle.setText("Выполняемые инструкции из APK. Не Java-декомпиляция.");
        search.setVisibility(View.GONE);
        listing.removeAllViews();listing.addView(text("Декодируем инструкции…",14,MUTED));
        DexCodeReader.Item item=currentClass;
        worker.execute(()->{
            try{
                String code=reader.disassemble(item,m);
                runOnUiThread(()->{
                    if(isFinishing()||isDestroyed()||currentClass!=item||currentMethod!=m)return;
                    currentCode=code;renderCode();
                });
            }catch(Exception e){runOnUiThread(()->showError(e));}
        });
    }
    private void renderCode(){
        listing.removeAllViews();
        listing.addView(button("Копировать код метода",()->{
            ClipboardManager cb=(ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
            if(cb!=null)cb.setPrimaryClip(ClipData.newPlainText("DEX / Smali",currentCode));
        }),new LinearLayout.LayoutParams(-1,dp(46)));
        listing.addView(button("Поделиться текстовым фрагментом",()->{
            Intent share=new Intent(Intent.ACTION_SEND);
            share.setType("text/plain");share.putExtra(Intent.EXTRA_TEXT,currentCode);
            startActivity(Intent.createChooser(share,"Поделиться"));
        }),new LinearLayout.LayoutParams(-1,dp(46)));
        TextView code=text(currentCode,12,TXT);
        code.setTextIsSelectable(true);
        code.setTypeface(Typeface.MONOSPACE);code.setHorizontallyScrolling(true);
        HorizontalScrollView hs=new HorizontalScrollView(this);
        hs.setFillViewport(false);hs.addView(code,new HorizontalScrollView.LayoutParams(-2,-2));
        listing.addView(hs);
    }
    private void showError(Exception e){
        if(isFinishing()||isDestroyed())return;
        listing.removeAllViews();
        listing.addView(text("Не удалось декодировать: "+e.getMessage(),14,MUTED));
    }
    @Override public void onBackPressed(){
        if(page==2){
            page=1;currentMethod=null;search.setVisibility(View.VISIBLE);search.setText("");
            renderList();
        }else if(page==1){
            page=0;currentClass=null;methods.clear();search.setVisibility(View.VISIBLE);search.setText("");
            renderList();
        }else super.onBackPressed();
    }
    @Override protected void onDestroy(){
        worker.shutdownNow();
        super.onDestroy();
    }
}
