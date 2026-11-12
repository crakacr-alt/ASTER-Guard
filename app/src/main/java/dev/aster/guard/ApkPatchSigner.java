package dev.aster.guard;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import javax.security.auth.x500.X500Principal;

/**
 * APK editor for explicitly selected, authorized APKs. ARSCLib edits binary
 * AndroidManifest.xml; apksig creates fresh v1/v2/v3 signatures with a
 * separately generated user-owned Android Keystore RSA key.
 *
 * No payment/license bypass. Does not execute APK payloads, modify a third
 * party's original signing certificate, or promise Android API compatibility.
 */
public final class ApkPatchSigner {
    public static final long MAX_APK=96L*1024*1024;
    private static final long MAX_UNCOMPRESSED=256L*1024*1024;
    private static final int MAX_ENTRIES=12000;
    private static final String PREFIX="aster_editor_user_";
    private static final Pattern CONFIG=Pattern.compile(
        "(?i)(\"(?:ads_enabled|advertising_enabled|analytics_enabled|tracking_enabled|"
        +"enable_ads|enable_tracking|enable_analytics|collect_analytics)\"\\s*:\\s*)true\\b");

    public static final int REBUILD=0,PRIVACY_CONFIG=1,REMOVE_ASSET=2;
    private ApkPatchSigner(){}

    private static String alias(String label){
        if(label==null||!label.matches("[A-Za-z][A-Za-z0-9_-]{2,27}"))
            throw new IllegalArgumentException("Имя ключа: латинские буквы, цифры, _/-, длина 3–28");
        return PREFIX+label;
    }
    private static KeyStore keyStore()throws Exception{
        KeyStore ks=KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);return ks;
    }
    public static boolean exists(String label)throws Exception{
        return keyStore().containsAlias(alias(label));
    }
    public static String createKey(String label)throws Exception{
        String name=alias(label);
        if(exists(label))throw new IOException("Этот ключ уже создан. Он не будет заменён.");
        KeyPairGenerator gen=KeyPairGenerator.getInstance("RSA","AndroidKeyStore");
        gen.initialize(new KeyGenParameterSpec.Builder(
            name,KeyProperties.PURPOSE_SIGN|KeyProperties.PURPOSE_VERIFY)
            .setKeySize(3072)
            .setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA512)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setCertificateSubject(new X500Principal("CN=ASTER User APK Key "+label))
            .setCertificateNotBefore(new java.util.Date(System.currentTimeMillis()-86400000L))
            .setCertificateNotAfter(new java.util.Date(System.currentTimeMillis()+8L*365*86400000L))
            .setUserAuthenticationRequired(false)
            .build());
        gen.generateKeyPair();
        return certificateSha256(label);
    }
    public static String certificateSha256(String label)throws Exception{
        java.security.cert.Certificate cert=keyStore().getCertificate(alias(label));
        if(cert==null)throw new IllegalArgumentException("Указанный ключ ещё не создан");
        return hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
    }

    public static final class Plan {
        public int minSdk=-1,targetSdk=-1;
        public int mode=REBUILD;
        public String removeAsset="";
    }
    public static final class Result {
        public final File file;
        public final String hash,certificateHash;
        public final boolean verified;
        public final int changedConfigurations,removedAssets,oldMinSdk,newMinSdk,oldTargetSdk,newTargetSdk;
        Result(File file,String hash,String cert,boolean verified,int edited,int removed,
               int oldMin,int newMin,int oldTarget,int newTarget){
            this.file=file;this.hash=hash;this.certificateHash=cert;this.verified=verified;
            this.changedConfigurations=edited;this.removedAssets=removed;
            this.oldMinSdk=oldMin;this.newMinSdk=newMin;
            this.oldTargetSdk=oldTarget;this.newTargetSdk=newTarget;
        }
    }
    public static final class ManifestInfo {
        public final String packageName;
        public final int minSdk,targetSdk;
        ManifestInfo(String pkg,int min,int target){packageName=pkg;minSdk=min;targetSdk=target;}
    }
    public static ManifestInfo manifest(File apk)throws Exception {
        try(ZipFile zip=new ZipFile(apk)){
            ZipEntry entry=zip.getEntry("AndroidManifest.xml");
            if(entry==null)throw new IOException("Нет AndroidManifest.xml: это не базовый APK");
            if(entry.getSize()>2*1024*1024)throw new IOException("AndroidManifest.xml превышает 2 МиБ");
            try(InputStream input=zip.getInputStream(entry)){
                AndroidManifestBlock manifest=AndroidManifestBlock.load(input);
                Integer min=manifest.getMinSdkVersion(),target=manifest.getTargetSdkVersion();
                return new ManifestInfo(manifest.getPackageName(),
                    min==null?1:min,target==null?1:target);
            }
        }
    }
    public static String[] assets(File apk)throws IOException{
        ArrayList<String> found=new ArrayList<>();
        try(ZipFile zip=new ZipFile(apk)){
            Enumeration<? extends ZipEntry> e=zip.entries();
            int n=0;
            while(e.hasMoreElements()&&n++<MAX_ENTRIES){
                String path=e.nextElement().getName();
                if(allowedAsset(path)&&found.size()<100)found.add(path);
            }
        }
        Collections.sort(found);
        return found.toArray(new String[0]);
    }
    private static boolean allowedAsset(String s){
        return s!=null&&s.startsWith("assets/")&&!s.endsWith("/")&&
            s.length()<220&&!s.contains("..")&&!s.contains("\\");
    }
    private static boolean oldSignature(String path){
        if(!path.startsWith("META-INF/"))return false;
        String n=path.substring(9).toUpperCase(Locale.ROOT);
        return n.endsWith(".SF")||n.endsWith(".RSA")||n.endsWith(".DSA")||
            n.endsWith(".EC")||n.startsWith("SIG-")||n.equals("MANIFEST.MF");
    }
    private static byte[] readBounded(InputStream in,int max)throws IOException{
        ByteArrayOutputStream out=new ByteArrayOutputStream(Math.min(max,64*1024));
        byte[] buf=new byte[32768];int n;
        while((n=in.read(buf))!=-1){
            if(out.size()+(long)n>max)throw new IOException("Чтение превысило лимит "+max+" байт");
            out.write(buf,0,n);
        }
        return out.toByteArray();
    }
    private static String hex(byte[] bytes){
        StringBuilder s=new StringBuilder();
        for(byte b:bytes)s.append(String.format(Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    private static String fileSha(File file)throws Exception{
        MessageDigest d=MessageDigest.getInstance("SHA-256");
        try(InputStream in=new FileInputStream(file)){
            byte[] b=new byte[65536];int n;
            while((n=in.read(b))!=-1)d.update(b,0,n);
        }
        return hex(d.digest());
    }
    /**
     * Repackages into a new archive and signs it. When native libraries
     * require special alignment, this simple editor rejects the APK instead
     * of producing an "installed" claim for an invalid binary.
     */
    public static Result rebuildAndSign(File original,File output,String key,Plan plan)throws Exception{
        if(original==null||!original.isFile()||original.length()<4||original.length()>MAX_APK)
            throw new IOException("Выберите APK размером не больше 96 МиБ");
        if(output==null||original.getCanonicalFile().equals(output.getCanonicalFile()))
            throw new IOException("Выходной файл должен отличаться от оригинала");
        if(plan==null||plan.mode<REBUILD||plan.mode>REMOVE_ASSET)
            throw new IllegalArgumentException("Неизвестный тип изменения");
        if(plan.mode==REMOVE_ASSET&&!allowedAsset(plan.removeAsset))
            throw new IllegalArgumentException("Удалять разрешено только выбранный файл assets/");
        if(plan.minSdk>0 && (plan.minSdk<1||plan.minSdk>36))
            throw new IllegalArgumentException("minSdk должен быть от 1 до 36");
        if(plan.targetSdk>0&&(plan.targetSdk<1||plan.targetSdk>36))
            throw new IllegalArgumentException("targetSdk должен быть от 1 до 36");
        KeyStore ks=keyStore();
        PrivateKey privateKey=(PrivateKey)ks.getKey(alias(key),null);
        X509Certificate cert=(X509Certificate)ks.getCertificate(alias(key));
        if(privateKey==null||cert==null)throw new IOException("Сначала создайте собственный ключ");
        File unsigned=File.createTempFile("aster-editor-",".apk",output.getParentFile());
        int changed=0,removed=0,oldMin=0,oldTarget=0,newMin=0,newTarget=0;
        boolean hadManifest=false,assetFound=false,nativeLibs=false;
        long expanded=0;
        Set<String> seen=new HashSet<>();
        try {
            try(ZipFile input=new ZipFile(original);
                ZipOutputStream zip=new ZipOutputStream(new FileOutputStream(unsigned))){
                Enumeration<? extends ZipEntry> entries=input.entries();
                int entryCount=0;
                while(entries.hasMoreElements()){
                    if(++entryCount>MAX_ENTRIES)throw new IOException("ZIP содержит слишком много записей");
                    if(Thread.currentThread().isInterrupted())throw new IOException("Пересборка отменена");
                    ZipEntry src=entries.nextElement();
                    String path=src.getName();
                    if(path.contains("..")||path.startsWith("/")||path.contains("\\"))
                        throw new IOException("Небезопасный путь ZIP: "+path);
                    if(!seen.add(path))throw new IOException("Повторяющаяся запись: "+path);
                    if(oldSignature(path))continue;
                    if(plan.mode==REMOVE_ASSET&&path.equals(plan.removeAsset)){
                        removed++;assetFound=true;continue;
                    }
                    byte[] replacement=null;
                    if(path.equals("AndroidManifest.xml")){
                        hadManifest=true;
                        try(InputStream in=input.getInputStream(src)){
                            AndroidManifestBlock manifest=AndroidManifestBlock.load(in);
                            Integer x=manifest.getMinSdkVersion(),y=manifest.getTargetSdkVersion();
                            oldMin=x==null?1:x;oldTarget=y==null?1:y;
                            newMin=oldMin;newTarget=oldTarget;
                            if(plan.minSdk>0&&plan.minSdk!=oldMin){
                                manifest.setMinSdkVersion(plan.minSdk);newMin=plan.minSdk;
                            }
                            if(plan.targetSdk>0&&plan.targetSdk!=oldTarget){
                                manifest.setTargetSdkVersion(plan.targetSdk);newTarget=plan.targetSdk;
                            }
                            replacement=manifest.getBytes();
                            if(replacement.length>2*1024*1024)
                                throw new IOException("Изменённый манифест слишком большой");
                        }
                    } else if(plan.mode==PRIVACY_CONFIG&&allowedAsset(path)&&
                        path.toLowerCase(Locale.ROOT).endsWith(".json")&&
                        src.getSize()>=0&&src.getSize()<256*1024){
                        try(InputStream in=input.getInputStream(src)){
                            byte[] originalJson=readBounded(in,256*1024);
                            String text=new String(originalJson,java.nio.charset.StandardCharsets.UTF_8);
                            java.util.regex.Matcher matcher=CONFIG.matcher(text);
                            StringBuffer buf=new StringBuffer();
                            boolean found=false;
                            while(matcher.find()){
                                found=true;changed++;
                                matcher.appendReplacement(buf,java.util.regex.Matcher.quoteReplacement(
                                    matcher.group(1)+"false"));
                            }
                            if(found){
                                matcher.appendTail(buf);
                                replacement=buf.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                            }
                        }
                    }
                    ZipEntry dst=new ZipEntry(path);
                    dst.setTime(src.getTime());
                    // Native libs may depend on APK ZIP mmap/page alignment. Reject
                    // such archives rather than silently breaking extractNativeLibs=false.
                    if(path.startsWith("lib/")&&path.endsWith(".so"))nativeLibs=true;
                    zip.putNextEntry(dst);
                    if(replacement!=null){
                        expanded+=replacement.length;
                        if(expanded>MAX_UNCOMPRESSED)throw new IOException("ZIP-bomb protection");
                        zip.write(replacement);
                    }else{
                        try(InputStream in=input.getInputStream(src)){
                            byte[] buf=new byte[32768];int n;
                            while((n=in.read(buf))!=-1){
                                expanded+=n;
                                if(expanded>MAX_UNCOMPRESSED)throw new IOException("ZIP-bomb protection");
                                zip.write(buf,0,n);
                            }
                        }
                    }
                    zip.closeEntry();
                }
            }
            if(!hadManifest)throw new IOException("APK не содержит AndroidManifest.xml");
            if(nativeLibs)throw new IOException(
                "В APK есть нативные .so. Для безопасной пересборки нужен zipalign/page-align; этот режим пока не поддерживает нативные APK.");
            if(plan.mode==REMOVE_ASSET&&!assetFound)
                throw new IOException("Выбранный assets/ файл отсутствует");
            if(plan.mode==PRIVACY_CONFIG&&changed==0)
                throw new IOException("В assets/*.json не найдены явно заданные параметры отключения аналитики");
            ApkSigner.SignerConfig signer=new ApkSigner.SignerConfig.Builder(
                key,privateKey,Collections.singletonList(cert)).build();
            new ApkSigner.Builder(Collections.singletonList(signer))
                .setInputApk(unsigned)
                .setOutputApk(output)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build().sign();
            ApkVerifier.Result verified=new ApkVerifier.Builder(output).build().verify();
            if(!verified.isVerified()){
                output.delete();
                throw new IOException("Подпись результата не прошла проверку ApkVerifier");
            }
            return new Result(output,fileSha(output),certificateSha256(key),true,changed,removed,
                oldMin,newMin,oldTarget,newTarget);
        }catch(Exception error){
            output.delete();throw error;
        }finally{
            unsigned.delete();
        }
    }
}
