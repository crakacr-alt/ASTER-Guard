package dev.aster.guard;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Privacy-preserving, read-only, best-effort file analyzer.
 *
 * Processes SAF InputStreams, not filesystem paths. Never runs executable code,
 * never executes document macros, never extracts archives onto storage.
 * Results are *structural indicators*, not virus or exploit verdicts.
 */
public final class FileInspector {
    public static final long MAX_FILE_BYTES=512L*1024*1024;
    public static final long MAX_ZIP_INFLATED=64L*1024*1024;
    public static final int MAX_ZIP_ENTRIES=1200;
    private static final int MAX_TEXT_SCAN=8*1024*1024;
    private static final int MAX_ENTRY_SNIPPET=256*1024;
    private static final int MAX_FINDINGS=48;
    public static final int INFO=0, CAUTION=1, IMPORTANT=2;

    public static final class Finding {
        public final int severity;
        public final String title, explanation;
        Finding(int level,String title,String explanation){
            this.severity=level;this.title=title;this.explanation=explanation;
        }
    }
    public static final class Report {
        public String name="",extension="",mime="",format="Неизвестный двоичный файл",sha256="";
        public long bytesRead,declaredSize=-1,expandedBytes;
        public boolean complete=true,zipPartial,archive,apk,office,pdf,executable;
        public int entries,classesDex,nativeLibraries,embeddedExecutables,macroFiles;
        public final List<Finding> findings=new ArrayList<>();
        private final Set<String> seen=new LinkedHashSet<>();
        void add(int severity,String key,String explanation){
            if(findings.size()>=MAX_FINDINGS||!seen.add(key))return;
            findings.add(new Finding(severity,key,explanation));
        }
        public String confidence(){
            if(!complete||zipPartial)return "Частичная проверка — нет основания считать файл безопасным";
            if(findings.stream().anyMatch(f->f.severity==IMPORTANT))
                return "Обнаружены потенциально опасные элементы — требуется разбор";
            if(findings.stream().anyMatch(f->f.severity==CAUTION))
                return "Есть индикаторы, требующие внимания; вредоносность не доказана";
            return "Явных структурных индикаторов не найдено — это НЕ гарантия безопасности";
        }
    }
    public interface Progress {void onBytes(long bytes);}
    private FileInspector(){}

    public static Report analyze(InputStream source,InputStream archiveSource,String name,String mime,long size,
                                  BooleanSupplier cancelled,Progress progress)throws IOException {
        if(source==null)throw new IOException("Файл недоступен");
        if(cancelled==null)cancelled=()->false;
        Report r=new Report();
        r.name=name==null?"Без названия":name;r.mime=mime==null?"":mime;
        r.declaredSize=size;
        String lower=r.name.toLowerCase(Locale.ROOT);
        int dot=lower.lastIndexOf('.');
        r.extension=dot<0?"":lower.substring(dot+1);
        BufferedInputStream input=new BufferedInputStream(source,64*1024);
        input.mark(8192);
        byte[] header=new byte[4096];
        int length=0,n;
        while(length<header.length&&(n=input.read(header,length,header.length-length))>0)length+=n;
        input.reset();
        r.format=detect(header,length);
        r.archive="ZIP / APK / Office Open XML".equals(r.format);
        r.office=isOffice(r.extension);
        r.pdf="PDF".equals(r.format);
        r.executable=isExe(r.format);
        r.apk=("apk".equals(r.extension)||"apks".equals(r.extension)||"xapk".equals(r.extension))&&r.archive;

        if(r.executable)r.add(CAUTION,"Исполняемый файл",
            "Сам по себе EXE/ELF не является вирусом. На Android он не запускается при проверке.");
        if(isMisnamed(r))r.add(CAUTION,"Расширение и содержимое отличаются",
            "Расширение ."+r.extension+" не соответствует сигнатуре («"+r.format+"»). Возможна ошибка имени или маскировка.");
        if("OLE Compound Document".equals(r.format)){
            r.add(INFO,"Старый двоичный Office/OLE",
                "DOC/XLS/PPT и другие OLE-контейнеры требуют отдельного парсера VBA: эта проверка не доказывает отсутствие макросов.");
        }
        if(isUnsupportedCompressed(r.format))r.add(INFO,"Ограниченное исследование архива",
            "Для RAR/7z/GZIP проверяются сигнатура и SHA-256. Внутренние файлы не распаковываются и не проверяются.");
        if(r.archive&&archiveSource==null)
            r.add(CAUTION,"Не удалось открыть ZIP повторно","Можно проверить только сигнатуру и SHA-256; содержимое не исследовано.");

        MessageDigest digest;
        try{digest=MessageDigest.getInstance("SHA-256");}
        catch(Exception e){throw new IOException("SHA-256 недоступен",e);}
        byte[] buffer=new byte[64*1024];
        String tail="";int scanned=0,loops=0;
        while((n=input.read(buffer))!=-1){
            if(cancelled.getAsBoolean()||Thread.currentThread().isInterrupted())throw new IOException("Проверка отменена");
            if(r.bytesRead+n>MAX_FILE_BYTES){
                r.complete=false;
                r.add(CAUTION,"Лимит чтения",
                    "Прочитано не более 512 МиБ. Полный SHA-256 не вычислен; файл не исследован целиком.");
                break;
            }
            digest.update(buffer,0,n);
            r.bytesRead+=n;
            if(scanned<MAX_TEXT_SCAN){
                int take=Math.min(n,MAX_TEXT_SCAN-scanned);
                String block=tail+new String(buffer,0,take,StandardCharsets.ISO_8859_1);
                inspectText(block,r);
                tail=block.substring(Math.max(0,block.length()-250));
                scanned+=take;
            }
            if(progress!=null && ++loops%16==0)progress.onBytes(r.bytesRead);
        }
        if(r.complete)r.sha256=hex(digest.digest());
        if(r.bytesRead==0)r.add(CAUTION,"Пустой файл","В файле нет содержимого для структурного анализа.");
        if(r.pdf)r.add(INFO,"Ограничения PDF",
            "Проверяется открытый текстовый слой первых 8 МиБ. Сжатые объекты, JavaScript в потоках и повреждённые структуры могут быть пропущены.");
        if(r.office&&!r.archive&&!"OLE Compound Document".equals(r.format))
            r.add(CAUTION,"Необычный документ","Формат Office не удалось подтвердить по сигнатуре.");

        if(r.archive&&archiveSource!=null){
            try{
                inspectZip(archiveSource,r,cancelled);
            }catch(IOException | RuntimeException ex){
                r.zipPartial=true;
                r.add(CAUTION,"ZIP исследован не полностью",
                    "Архив повреждён, зашифрован или содержит неподдерживаемые структуры: "+ex.getClass().getSimpleName());
            }
        }
        if(r.archive){
            if(r.classesDex>0 && r.apk)r.add(INFO,"DEX-код в APK",
                "Найдено файлов classes*.dex: "+r.classesDex+". Доступен отдельный DEX/Smali-просмотр.");
            if(r.classesDex==0 && r.apk)r.add(CAUTION,"В APK нет очевидного classes.dex",
                "Это бывает для ресурсов, split APK, контейнеров APK и нетипичных сборок.");
            if(r.nativeLibraries>0)r.add(INFO,"Нативные библиотеки",
                "Найдено .so: "+r.nativeLibraries+". Исполняемый машинный код в этом режиме не декомпилируется.");
        }
        return r;
    }

    public static String detect(byte[] b,int n){
        if(n>=8&&match(b,0,0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a))return "PNG";
        if(n>=5&&match(b,0,0x25,0x50,0x44,0x46,0x2d))return "PDF";
        if(n>=4&&match(b,0,0x50,0x4b,0x03,0x04))return "ZIP / APK / Office Open XML";
        if(n>=4&&match(b,0,0x50,0x4b,0x05,0x06))return "ZIP / APK / Office Open XML";
        if(n>=4&&match(b,0,0x50,0x4b,0x07,0x08))return "ZIP / APK / Office Open XML";
        if(n>=8&&match(b,0,0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1))return "OLE Compound Document";
        if(n>=4&&match(b,0,0x7f,0x45,0x4c,0x46))return "ELF executable";
        if(n>=2&&match(b,0,0x4d,0x5a)){
            if(n>=64){
                int off=(b[0x3c]&255)|((b[0x3d]&255)<<8)|((b[0x3e]&255)<<16)|((b[0x3f]&255)<<24);
                if(off>=0&&off+4<=n && match(b,off,0x50,0x45,0x00,0x00))return "Windows PE executable";
            }
            return "Windows MZ (PE unconfirmed)";
        }
        if(n>=3&&match(b,0,0x52,0x61,0x72))return "RAR archive";
        if(n>=6&&match(b,0,0x37,0x7a,0xbc,0xaf,0x27,0x1c))return "7z archive";
        if(n>=2&&match(b,0,0x1f,0x8b))return "GZIP";
        if(n>=3&&match(b,0,0xff,0xd8,0xff))return "JPEG";
        if(n>=6&&new String(b,0,6,StandardCharsets.US_ASCII).startsWith("GIF8"))return "GIF";
        if(n>=12&&new String(b,0,4,StandardCharsets.US_ASCII).equals("RIFF")&&
            new String(b,8,4,StandardCharsets.US_ASCII).equals("WEBP"))return "WEBP";
        if(n>=4&&match(b,0,0x00,0x61,0x73,0x6d))return "WebAssembly executable";
        if(n>=4&&match(b,0,0xca,0xfe,0xba,0xbe))return "Java class";
        if(n>=16&&new String(b,0,16,StandardCharsets.US_ASCII).equals("SQLite format 3\u0000"))return "SQLite database";
        if(n>=4&&new String(b,0,4,StandardCharsets.US_ASCII).equals("dex\n"))return "DEX bytecode";
        if(n>=3&&new String(b,0,3,StandardCharsets.US_ASCII).equals("ID3"))return "MP3 audio";
        if(n>=4&&new String(b,0,Math.min(100,n),StandardCharsets.ISO_8859_1).trim().startsWith("{\\rtf"))return "RTF document";
        if(n>=2&&b[0]=='#'&&b[1]=='!')return "Script text";
        String prefix=new String(b,0,Math.min(n,128),StandardCharsets.ISO_8859_1).trim().toLowerCase(Locale.ROOT);
        if(prefix.startsWith("<!doctype html")||prefix.startsWith("<html"))return "HTML document";
        if(prefix.startsWith("<?xml"))return "XML text";
        return n==0?"Empty file":"Unknown (signature not recognized)";
    }
    private static boolean match(byte[] b,int at,int... sig){
        if(at<0||at+sig.length>b.length)return false;
        for(int i=0;i<sig.length;i++)if((b[at+i]&255)!=sig[i])return false;
        return true;
    }
    private static boolean isExe(String s){return s.contains("executable")||s.startsWith("Windows MZ");}
    private static boolean isUnsupportedCompressed(String s){
        return s.equals("RAR archive")||s.equals("7z archive")||s.equals("GZIP");
    }
    private static boolean isOffice(String e){
        return e.matches("doc|docx|docm|dot|dotm|dotx|xls|xlsx|xlsm|ppt|pptx|pptm|pps|ppsx|ppsm|ppts|odt|ods|odp|rtf");
    }
    private static boolean isMisnamed(Report r){
        String e=r.extension,f=r.format;
        if(e.isEmpty())return false;
        if(e.equals("apk")||e.equals("apks")||e.equals("xapk")||e.equals("zip")||e.equals("jar")||e.equals("docx")||
           e.equals("xlsx")||e.equals("pptx")||e.equals("pptm")||e.equals("docm")||e.equals("xlsm")||
           e.equals("ppsx")||e.equals("ppsm")||e.equals("odt")||e.equals("ods")||e.equals("odp"))
            return !r.archive;
        if(e.equals("exe")||e.equals("dll")||e.equals("sys"))return !f.startsWith("Windows");
        if(e.equals("pdf"))return !f.equals("PDF");
        if(e.equals("png"))return !f.equals("PNG");
        if(e.equals("jpg")||e.equals("jpeg"))return !f.equals("JPEG");
        if(e.equals("gif"))return !f.equals("GIF");
        if(e.equals("webp"))return !f.equals("WEBP");
        if(e.equals("doc")||e.equals("xls")||e.equals("ppt")||e.equals("pps")||e.equals("ppts"))
            return !f.equals("OLE Compound Document");
        return false;
    }
    private static void inspectText(String input,Report r){
        if(!r.pdf&&!r.format.equals("RTF document")&&!r.format.equals("Script text")&&!r.format.equals("HTML document"))
            return;
        String s=input.toLowerCase(Locale.ROOT);
        if(r.pdf){
            if(s.contains("/javascript")||s.contains("/js ")||s.contains("/js\n"))
                r.add(CAUTION,"PDF содержит JavaScript-маркеры",
                    "В открытом PDF обнаружены /JavaScript или /JS. Это законная функция PDF, но также используется в атаках.");
            if(s.contains("/openaction")||s.contains("/aa "))
                r.add(CAUTION,"PDF содержит действия при открытии",
                    "Маркеры /OpenAction или /AA означают действия/события. Это не доказывает эксплуатацию.");
            if(s.contains("/launch"))
                r.add(IMPORTANT,"PDF содержит /Launch",
                    "Возможен запрос запуска внешней программы при открытии PDF. Не открывайте документ в устаревших просмотрщиках.");
            if(s.contains("/embeddedfile")||s.contains("/filespec"))
                r.add(CAUTION,"В PDF есть признаки вложенного файла",
                    "Найдены маркеры вложений. Вложенные данные не исполняются и не извлекаются.");
            if(s.contains("/encrypt"))r.add(CAUTION,"В PDF обнаружен /Encrypt",
                "Часть содержимого может быть зашифрована: структурная проверка ограничена.");
        }else if(r.format.equals("RTF document")){
            if(s.contains("\\object")||s.contains("\\objdata"))
                r.add(CAUTION,"RTF содержит вложенный объект","Объекты OLE могут переносить исполняемое содержимое.");
            if(s.contains("\\field")&&s.contains("dde"))
                r.add(CAUTION,"RTF содержит признаки DDE","Проверьте документ в изолированной среде.");
        }else{
            if(s.contains("powershell -enc")||s.contains("frombase64string")||
               s.contains("eval(atob("))
                r.add(CAUTION,"Обфускация или запуск скрипта",
                    "Найдены текстовые маркеры закодированных команд. Совпадение не означает вредоносность.");
        }
    }
    private static void inspectZip(InputStream stream,Report r,BooleanSupplier cancelled)throws IOException{
        try(ZipInputStream zip=new ZipInputStream(new BufferedInputStream(stream,64*1024))){
            ZipEntry entry;
            byte[] buf=new byte[16*1024];
            while((entry=zip.getNextEntry())!=null){
                if(cancelled.getAsBoolean()||Thread.currentThread().isInterrupted())throw new IOException("Проверка отменена");
                if(++r.entries>MAX_ZIP_ENTRIES){
                    r.zipPartial=true;r.add(CAUTION,"Лимит архива","Просмотрено не более 1200 ZIP-записей.");break;
                }
                String name=entry.getName(),s=name.replace('\\','/').toLowerCase(Locale.ROOT);
                if(s.startsWith("/")||s.startsWith("../")||s.contains("/../")){
                    r.add(CAUTION,"ZIP содержит путь вне архива",
                        "Вложенная запись содержит ../ или абсолютный путь. ASTER ничего не извлекает на диск.");
                }
                if(s.matches("classes[0-9]*\\.dex"))r.classesDex++;
                if(s.startsWith("lib/")&&s.endsWith(".so"))r.nativeLibraries++;
                if(s.endsWith("vbaproject.bin")||s.endsWith("/vba.bin")){
                    r.macroFiles++;
                    r.add(IMPORTANT,"Office-документ содержит VBA-макросы",
                        "Найден файл vbaProject.bin или vba.bin. Макросы не запускаются; наличие может быть легитимным.");
                }
                if(s.contains("/activex/")||s.contains("/embeddings/")||s.contains("/oleobject")){
                    r.add(CAUTION,"Office содержит активные/вложенные объекты",
                        "В документе присутствуют ActiveX, OLE или вложения. Исходный код вложений не декомпилируется.");
                }
                if(s.endsWith(".exe")||s.endsWith(".dll")||s.endsWith(".bat")||
                    s.endsWith(".cmd")||s.endsWith(".ps1")||s.endsWith(".scr")||
                    s.endsWith(".js")||s.endsWith(".vbs")||s.endsWith(".apk")||
                    s.endsWith(".jar")||s.endsWith(".dex")||s.endsWith(".so")){
                    r.embeddedExecutables++;
                    if(r.embeddedExecutables<=5)r.add(CAUTION,"Вложенный исполняемый или скриптовый файл: "+crop(s,100),
                        "Имя вложения требует внимания; само по себе присутствие не доказывает заражение.");
                }
                if(entry.isDirectory())continue;
                long per=0;
                ByteArrayOutputStream sample=null;
                boolean rels=s.endsWith(".rels")||s.endsWith("document.xml")||
                    s.endsWith("workbook.xml")||s.endsWith("presentation.xml");
                if(rels)sample=new ByteArrayOutputStream(2048);
                int n;
                while((n=zip.read(buf))!=-1){
                    if(cancelled.getAsBoolean()||Thread.currentThread().isInterrupted())throw new IOException("Проверка отменена");
                    per+=n;r.expandedBytes+=n;
                    if(sample!=null && sample.size()<MAX_ENTRY_SNIPPET)
                        sample.write(buf,0,Math.min(n,MAX_ENTRY_SNIPPET-sample.size()));
                    if(r.expandedBytes>MAX_ZIP_INFLATED){
                        r.zipPartial=true;r.add(CAUTION,"Лимит распаковки ZIP",
                            "После 64 МиБ распакованных данных анализ остановлен для защиты от ZIP-bomb.");
                        return;
                    }
                }
                if(sample!=null){
                    String xml=sample.toString("UTF-8").toLowerCase(Locale.ROOT);
                    if(xml.contains("targetmode=\"external\"")||xml.contains("targetmode='external'"))
                        r.add(CAUTION,"В Office-документе найдены внешние ссылки",
                            "Связи TargetMode=External могут быть обычными гиперссылками или удалёнными ресурсами.");
                    if(xml.contains("ddeauto")||xml.contains("dde "))
                        r.add(IMPORTANT,"Office содержит признаки DDE",
                            "Найдены поля DDE/DDEAUTO, которые могут запрашивать внешние данные или программы.");
                }
                zip.closeEntry();
            }
        }
    }
    private static String crop(String value,int max){return value.length()>max?value.substring(0,max)+"…":value;}
    private static String hex(byte[] b){
        StringBuilder sb=new StringBuilder(b.length*2);
        for(byte v:b)sb.append(String.format(Locale.ROOT,"%02x",v&255));
        return sb.toString();
    }
}
