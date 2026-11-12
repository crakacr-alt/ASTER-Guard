package dev.aster.guard;

import android.net.Uri;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Guest emulator controller; never hosts or executes a guest inside this phone.
 * Manual TLS certificate pin plus random bearer token required on every session.
 * No trust-all TLS, no cleartext traffic and no arbitrary ADB commands.
 */
public final class GuestLabClient {
    private static final int MAX_JSON=300*1024;
    private static final long MAX_BINARY=128L*1024*1024;
    private final String base,token;
    private final byte[] expectedFingerprint;
    private final javax.net.ssl.SSLSocketFactory factory;

    public GuestLabClient(String address,String fingerprint,String token)throws Exception {
        if(address==null||token==null||fingerprint==null)
            throw new IllegalArgumentException("Заполните HTTPS, сертификат и токен");
        String value=address.trim();
        URL u=new URL(value);
        if(!"https".equalsIgnoreCase(u.getProtocol())||
            u.getUserInfo()!=null||u.getQuery()!=null||u.getRef()!=null||
            !(u.getPath().isEmpty()||"/".equals(u.getPath()))||
            u.getHost().isEmpty())
            throw new IllegalArgumentException("Нужен адрес вида https://host:8742 без пути");
        if(u.getPort()<1||u.getPort()>65535)
            throw new IllegalArgumentException("Укажите порт HTTPS лаборатории");
        if(token.trim().length()<32||token.trim().length()>220)
            throw new IllegalArgumentException("Некорректный одноразовый токен лаборатории");
        this.base="https://"+u.getHost()+":"+u.getPort();
        this.token=token.trim();
        String pin=fingerprint.toUpperCase(Locale.ROOT).replace(":","").replace(" ","");
        if(!pin.matches("[0-9A-F]{64}"))
            throw new IllegalArgumentException("Укажите SHA-256 сертификата, 64 шестнадцатеричных символа");
        expectedFingerprint=hexBytes(pin);
        X509TrustManager verifier=new X509TrustManager(){
            @Override public void checkClientTrusted(X509Certificate[] chain,String auth)
                throws CertificateException {throw new CertificateException("No client certificate auth");}
            @Override public void checkServerTrusted(X509Certificate[] chain,String auth)
                throws CertificateException {
                if(chain==null||chain.length==0)throw new CertificateException("Нет сертификата");
                try{
                    byte[] actual=MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded());
                    if(!MessageDigest.isEqual(actual,expectedFingerprint))
                        throw new CertificateException("SHA-256 лаборатории не совпадает с указанным");
                }catch(CertificateException e){throw e;}
                catch(Exception e){throw new CertificateException("Нельзя проверить сертификат",e);}
            }
            @Override public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
        };
        SSLContext context=SSLContext.getInstance("TLS");
        context.init(null,new TrustManager[]{verifier},new java.security.SecureRandom());
        factory=context.getSocketFactory();
    }
    private static byte[] hexBytes(String hex){
        byte[] result=new byte[hex.length()/2];
        for(int i=0;i<result.length;i++)
            result[i]=(byte)Integer.parseInt(hex.substring(i*2,i*2+2),16);
        return result;
    }
    private HttpsURLConnection connection(String path,String method)throws IOException{
        if(!path.matches("/v1/[A-Za-z0-9/_-]+"))
            throw new IOException("Запрещённый адрес API");
        HttpsURLConnection conn=(HttpsURLConnection)new URL(base+path).openConnection();
        conn.setSSLSocketFactory(factory);
        // Only the manually pinned leaf certificate decides trust for private lab endpoints.
        conn.setHostnameVerifier((host,session)->true);
        conn.setConnectTimeout(6000);
        conn.setReadTimeout(90000);
        conn.setRequestMethod(method);
        conn.setRequestProperty("Authorization","Bearer "+token);
        conn.setRequestProperty("Accept","application/json");
        conn.setUseCaches(false);
        return conn;
    }
    private static byte[] limitedRead(InputStream in,int cap)throws IOException{
        ByteArrayOutputStream mem=new ByteArrayOutputStream(4096);
        byte[] buf=new byte[8192];int n,total=0;
        while((n=in.read(buf))!=-1){
            total+=n;if(total>cap)throw new IOException("Ответ лаборатории превышает лимит");
            mem.write(buf,0,n);
        }
        return mem.toByteArray();
    }
    private JSONObject response(HttpsURLConnection conn)throws Exception{
        try{
            int code=conn.getResponseCode();
            try(InputStream stream=code>=400?conn.getErrorStream():conn.getInputStream()){
                if(stream==null)throw new IOException("Пустой ответ HTTPS "+code);
                JSONObject body=new JSONObject(new String(limitedRead(stream,MAX_JSON),"UTF-8"));
                if(code>=400)throw new IOException("Лаборатория HTTP "+code+": "+body.optString("error","ошибка"));
                return body;
            }
        }finally{conn.disconnect();}
    }
    public JSONObject get(String path)throws Exception{
        return response(connection(path,"GET"));
    }
    public JSONObject post(String path,JSONObject data)throws Exception{
        return postJson(path,data,8192,90000);
    }
    private JSONObject postJson(String path,JSONObject data,int cap,int readTimeout)throws Exception{
        HttpsURLConnection conn=connection(path,"POST");
        conn.setDoOutput(true);
        conn.setReadTimeout(readTimeout);
        byte[] bytes=data.toString().getBytes("UTF-8");
        if(bytes.length>cap)throw new IOException("Слишком большой запрос");
        conn.setRequestProperty("Content-Type","application/json");
        conn.setFixedLengthStreamingMode(bytes.length);
        try(OutputStream out=conn.getOutputStream()){out.write(bytes);}
        return response(conn);
    }
    /** User explicitly selected one UTF-8 C/C++ source file (up to 64 KiB). */
    public JSONObject buildNative(byte[] code,String language,String[] abis,int api,String library)throws Exception{
        if(code==null||code.length<1||code.length>64*1024)
            throw new IOException("Исходник должен быть от 1 до 64 КиБ");
        if(!"c".equals(language)&&!"cpp".equals(language))
            throw new IOException("Выберите C или C++");
        if(abis==null||abis.length<1||abis.length>4)
            throw new IOException("Выберите архитектуру");
        java.util.Set<String> choices=new java.util.HashSet<>(
            java.util.Arrays.asList("armeabi-v7a","arm64-v8a","x86","x86_64"));
        org.json.JSONArray targets=new org.json.JSONArray();
        for(String abi:abis){
            if(!choices.remove(abi))throw new IOException("Неверная архитектура");
            targets.put(abi);
        }
        if(api<24||api>35)throw new IOException("Android API 24–35");
        if(library==null||!library.matches("lib[A-Za-z0-9_]{1,48}\\.so"))
            throw new IOException("Имя должно иметь вид libexample.so");
        JSONObject payload=new JSONObject()
            .put("language",language).put("abis",targets).put("api",api)
            .put("library",library)
            .put("source_b64",android.util.Base64.encodeToString(code,android.util.Base64.NO_WRAP));
        return postJson("/v1/native/build",payload,150000,240000);
    }
    public JSONObject stageSandboxApk(File file)throws Exception{
        return uploadApkAt(file,"/v1/sandbox/stage");
    }
    public JSONObject uploadApk(File file)throws Exception{
        return uploadApkAt(file,"/v1/upload");
    }
    private JSONObject uploadApkAt(File file,String endpoint)throws Exception{
        if(!file.isFile()||file.length()<4||file.length()>96L*1024*1024)
            throw new IOException("Для гостевой установки требуется APK 1–96 МиБ");
        HttpsURLConnection conn=connection(endpoint,"POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type","application/vnd.android.package-archive");
        conn.setFixedLengthStreamingMode(file.length());
        try(OutputStream out=conn.getOutputStream();InputStream in=new FileInputStream(file)){
            byte[] buffer=new byte[64*1024];int n;
            while((n=in.read(buffer))!=-1){
                if(Thread.currentThread().isInterrupted())throw new IOException("Передача отменена");
                out.write(buffer,0,n);
            }
        }
        return response(conn);
    }
    /** Stream sensitive HPROF into a user-chosen SAF document, no global storage permission. */
    public String download(String id,OutputStream destination,String expectedHash)throws Exception{
        if(!id.matches("[0-9a-f]{32}"))throw new IOException("Неверный идентификатор дампа");
        HttpsURLConnection conn=connection("/v1/artifacts/"+id,"GET");
        conn.setRequestProperty("Accept","application/octet-stream");
        try{
            int responseCode=conn.getResponseCode();
            if(responseCode!=200)throw new IOException("Лаборатория HTTP "+responseCode);
            long expectedLength=conn.getContentLengthLong();
            if(expectedLength<0||expectedLength>MAX_BINARY)
                throw new IOException("Размер дампа неизвестен или превышает 128 МиБ");
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            long size=0;
            try(InputStream in=conn.getInputStream()){
                byte[] buffer=new byte[64*1024];int n;
                while((n=in.read(buffer))!=-1){
                    if(Thread.currentThread().isInterrupted())throw new IOException("Скачивание отменено");
                    size+=n;
                    if(size>MAX_BINARY)throw new IOException("Дамп превышает 128 МиБ");
                    digest.update(buffer,0,n);
                    destination.write(buffer,0,n);
                }
                destination.flush();
            }
            if(size!=expectedLength)throw new IOException("Дамп загрузился не полностью");
            StringBuilder actual=new StringBuilder();
            for(byte b:digest.digest())actual.append(String.format(Locale.ROOT,"%02x",b&255));
            if(expectedHash!=null&&!expectedHash.isEmpty()&&
                !actual.toString().equalsIgnoreCase(expectedHash))
                throw new IOException("Не совпадает SHA-256 дампа");
            return size+" байт, SHA-256 "+actual;
        }finally{conn.disconnect();}
    }
}
