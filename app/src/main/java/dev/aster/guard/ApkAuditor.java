package dev.aster.guard;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** On-demand static APK and split APK inspection, without executing untrusted bytes. */
public final class ApkAuditor {
    public static final class MavenPackage {
        public final String group,name,version;
        MavenPackage(String group,String name,String version){this.group=group;this.name=name;this.version=version;}
        @Override public String toString(){return group+":"+name+":"+version;}
        @Override public int hashCode(){return toString().hashCode();}
        @Override public boolean equals(Object a){return a instanceof MavenPackage&&toString().equals(a.toString());}
    }
    public static final class Audit {
        public String mainSha256="";
        public int archiveEntries, nativeLibraries, bundledApks, splitCount;
        public final DexInspector.Result dex=new DexInspector.Result();
        public final List<String> nativeNames=new ArrayList<>();
        public final Set<MavenPackage> exactMaven=new LinkedHashSet<>();
        public final List<String> warnings=new ArrayList<>();
    }
    private ApkAuditor(){}
    public static Audit scan(String[] files)throws IOException {
        Audit out=new Audit();
        if(files==null||files.length==0)throw new IOException("APK не найден");
        for(int index=0;index<Math.min(files.length,12);index++){
            String path=files[index];
            File file=new File(path);
            if(!file.isFile()) {out.warnings.add("Нет доступа к "+path);continue;}
            if(index==0)out.mainSha256=Hashing.fileSha256(file);
            if(index>0)out.splitCount++;
            try(ZipFile zip=new ZipFile(file)){
                Enumeration<? extends ZipEntry> entries=zip.entries();
                int n=0;
                while(entries.hasMoreElements()&&n<20000){
                    if(Thread.currentThread().isInterrupted())throw new IOException("Проверка остановлена");
                    ZipEntry e=entries.nextElement();n++;out.archiveEntries++;
                    String name=e.getName(),lower=name.toLowerCase(java.util.Locale.ROOT);
                    if(lower.startsWith("lib/")&&lower.endsWith(".so")){
                        out.nativeLibraries++;
                        if(out.nativeNames.size()<28)out.nativeNames.add(name);
                    }
                    if((lower.startsWith("assets/")||lower.startsWith("res/raw/")) &&
                        (lower.endsWith(".apk")||lower.endsWith(".dex")||lower.endsWith(".jar")))out.bundledApks++;
                    if(lower.matches("classes[0-9]*\\.dex")){
                        try(InputStream in=zip.getInputStream(e)){DexInspector.scan(in,e.getSize(),out.dex);}
                        catch(IOException ex){if(out.warnings.size()<20)out.warnings.add(name+": "+ex.getMessage());}
                    }
                    if(lower.startsWith("meta-inf/maven/")&&lower.endsWith("/pom.properties")
                        && e.getSize()<=32768 && out.exactMaven.size()<15){
                        Properties props=new Properties();
                        try(InputStream in=zip.getInputStream(e)){props.load(in);}
                        String group=props.getProperty("groupId","").trim();
                        String artifact=props.getProperty("artifactId","").trim();
                        String version=props.getProperty("version","").trim();
                        if(group.matches("[a-zA-Z0-9_.-]{2,120}") &&
                            artifact.matches("[a-zA-Z0-9_.-]{2,120}") &&
                            version.matches("[a-zA-Z0-9_.+\\-]{1,60}"))
                            out.exactMaven.add(new MavenPackage(group,artifact,version));
                    }
                }
                if(n>=20000)out.warnings.add("Лимит 20000 ZIP-записей достигнут");
            }
        }
        if(out.dex.skippedDex>0)out.warnings.add("Крупные DEX пропущены для экономии памяти: "+out.dex.skippedDex);
        if(out.exactMaven.isEmpty())out.warnings.add("Точные версии Maven-библиотек не обнаружены. По именам пакетов нельзя достоверно сопоставлять CVE.");
        out.warnings.add("DEX-классы и методы — статические ссылки, это НЕ трассировка работающего процесса.");
        return out;
    }
}
