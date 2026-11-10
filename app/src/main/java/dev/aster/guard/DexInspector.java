package dev.aster.guard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bounded, read-only DEX identifier and string inspector.
 * No decompilation, no execution, no false claim to live process debugging.
 */
public final class DexInspector {
    private static final int CAP_BYTES=24*1024*1024,MAX_STRINGS=220000,MAX_METHODS=320000;
    private static final Pattern URL=Pattern.compile("(?i)https?://([a-z0-9][a-z0-9.-]{1,190})(?::\\d{2,5})?(?:[/#?]|$)");
    private static final String[][] LIBS={
        {"Lokhttp3/","OkHttp (версия не установлена)"},{"Lretrofit2/","Retrofit (версия не установлена)"},
        {"Lcom/google/firebase/","Firebase (версия не установлена)"},
        {"Lcom/google/android/gms/ads/","Google Mobile Ads (версия не установлена)"},
        {"Lio/reactivex/","RxJava (версия не установлена)"},
        {"Landroidx/","AndroidX (версия не установлена)"},
        {"Lcom/facebook/ads/","Meta Ads (версия не установлена)"},
        {"Lorg/apache/http/","Apache HttpClient (версия не установлена)"}
    };
    private static final String[][] APIS={
        {"Ldalvik/system/DexClassLoader;","Динамическая загрузка DexClassLoader"},
        {"Ljava/lang/Runtime;","Runtime API"},
        {"Ljava/lang/ProcessBuilder;","ProcessBuilder API"},
        {"Ljava/lang/reflect/Method;","Reflection API"},
        {"Landroid/accessibilityservice/AccessibilityService;","Accessibility API"},
        {"Landroid/telephony/SmsManager;","SMS API"},
        {"Landroid/content/pm/PackageInstaller;","PackageInstaller API"},
        {"Landroid/webkit/WebView;","WebView API"},
        {"Ljavax/net/ssl/X509TrustManager;","TLS TrustManager API"},
        {"Ljavax/crypto/Cipher;","Cryptography API"}
    };
    public static final class Result {
        public int dexFiles,stringCount,classCount,methodIds,skippedDex;
        public final Set<String> classNames=new LinkedHashSet<>();
        public final Set<String> methodNames=new LinkedHashSet<>();
        public final Set<String> urls=new LinkedHashSet<>();
        public final Set<String> possibleLibs=new LinkedHashSet<>();
        public final Set<String> sensitiveApis=new LinkedHashSet<>();
    }
    private DexInspector(){}

    public static void scan(InputStream input,long size,Result out)throws IOException{
        if(size>CAP_BYTES){out.skippedDex++;return;}
        ByteArrayOutputStream mem=new ByteArrayOutputStream(65536);
        byte[] b=new byte[65536];int n,total=0;
        while((n=input.read(b))!=-1){
            total+=n;
            if(total>CAP_BYTES){out.skippedDex++;return;}
            mem.write(b,0,n);
            if(Thread.currentThread().isInterrupted())throw new IOException("Проверка остановлена");
        }
        scanBytes(mem.toByteArray(),out);
    }
    static void scanBytes(byte[] b,Result out)throws IOException{
        if(b.length<112||b[0]!='d'||b[1]!='e'||b[2]!='x'||b[3]!='\n')
            throw new IOException("Неверный заголовок DEX");
        int strCount=u32(b,56),strOff=u32(b,60);
        int typeCount=u32(b,64),typeOff=u32(b,68);
        int methodCount=u32(b,88),methodOff=u32(b,92);
        int classCount=u32(b,96),classOff=u32(b,100);
        check(b,strOff,strCount,4,MAX_STRINGS);
        check(b,typeOff,typeCount,4,MAX_STRINGS);
        check(b,methodOff,methodCount,8,MAX_METHODS);
        check(b,classOff,classCount,32,MAX_STRINGS);
        String[] pool=new String[strCount];
        for(int i=0;i<strCount;i++){
            int p=u32(b,strOff+i*4);
            if(p<0||p>=b.length)throw new IOException("DEX повреждён: строка вне диапазона");
            int k=0,byteValue;
            do{
                if(p>=b.length||k++>4)throw new IOException("Неверный DEX ULEB128");
                byteValue=b[p++]&0xff;
            }while((byteValue&0x80)!=0);
            int end=p;
            while(end<b.length&&b[end]!=0&&end-p<384)end++;
            String val=new String(b,p,end-p,StandardCharsets.UTF_8);
            pool[i]=val;
            if(out.urls.size()<48){
                Matcher matcher=URL.matcher(val);
                if(matcher.find())out.urls.add(matcher.group(1).toLowerCase(java.util.Locale.ROOT));
            }
        }
        out.dexFiles++;out.stringCount+=strCount;out.classCount+=classCount;out.methodIds+=methodCount;
        for(int i=0;i<classCount;i++){
            String value=type(b,typeOff,typeCount,u32(b,classOff+i*32),pool);
            mark(value,out);
            if(out.classNames.size()<80)out.classNames.add(value);
        }
        for(int i=0;i<methodCount;i++){
            int p=methodOff+i*8;
            String value=type(b,typeOff,typeCount,u16(b,p),pool);
            mark(value,out);
            int id=u32(b,p+4);
            if(id>=0&&id<pool.length && out.methodNames.size()<90
                && !value.startsWith("Ljava/")&&!value.startsWith("Landroid/")){
                out.methodNames.add(value+" -> "+pool[id]);
            }
        }
    }
    private static void mark(String clazz,Result r){
        for(String[] m:LIBS)if(clazz.startsWith(m[0]))r.possibleLibs.add(m[1]);
        for(String[] m:APIS)if(clazz.equals(m[0]))r.sensitiveApis.add(m[1]);
    }
    private static String type(byte[] b,int off,int count,int index,String[] strings){
        if(index<0||index>=count)return "?";
        int idx=u32(b,off+index*4);
        return idx<0||idx>=strings.length?"?":strings[idx];
    }
    private static void check(byte[] b,int off,int count,int stride,int max)throws IOException{
        if(off<0||count<0||count>max||(long)off+(long)count*stride>b.length)
            throw new IOException("Повреждённая таблица DEX");
    }
    private static int u16(byte[] b,int p){return (b[p]&255)|((b[p+1]&255)<<8);}
    private static int u32(byte[] b,int p){
        return (b[p]&255)|((b[p+1]&255)<<8)|((b[p+2]&255)<<16)|((b[p+3]&255)<<24);
    }
}
