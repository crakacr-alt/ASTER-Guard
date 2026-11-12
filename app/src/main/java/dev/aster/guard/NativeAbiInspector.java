package dev.aster.guard;

import android.os.Build;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** ELF class/machine audit: detects native ABI, never translates machine code. */
public final class NativeAbiInspector {
    private NativeAbiInspector(){}
    public static final class Elf {
        public final String abi;
        public final int bits,machine;
        public final boolean valid;
        Elf(String abi,int bits,int machine,boolean valid){
            this.abi=abi;this.bits=bits;this.machine=machine;this.valid=valid;
        }
        public String description(){
            return valid ? abi+" · ELF "+bits+" bit · e_machine="+machine
                : "Неизвестный или повреждённый ELF";
        }
    }
    public static final class Library {
        public final String path;
        public final Elf elf;
        public final boolean placementMatches;
        Library(String path,Elf elf){
            this.path=path;this.elf=elf;
            this.placementMatches=elf.valid&&path.startsWith("lib/"+elf.abi+"/");
        }
    }
    public static Elf header(byte[] b,int n){
        if(b==null||n<20||(b[0]&255)!=0x7f||b[1]!='E'||b[2]!='L'||b[3]!='F'){
            return new Elf("unknown",0,0,false);
        }
        int bits=(b[4]&255)==1?32:(b[4]&255)==2?64:0;
        int endian=b[5]&255;
        int machine=endian==1 ? ((b[18]&255)|((b[19]&255)<<8)) :
            endian==2 ? (((b[18]&255)<<8)|(b[19]&255)) : 0;
        String abi="unknown";
        if(bits==32&&machine==40)abi="armeabi-v7a";
        if(bits==64&&machine==183)abi="arm64-v8a";
        if(bits==32&&machine==3)abi="x86";
        if(bits==64&&machine==62)abi="x86_64";
        if(bits==64&&machine==243)abi="riscv64";
        return new Elf(abi,bits,machine,bits!=0&&!"unknown".equals(abi));
    }
    public static Elf inspect(File file)throws IOException{
        try(InputStream in=new FileInputStream(file)){return inspect(in);}
    }
    public static Elf inspect(InputStream input)throws IOException{
        byte[] first=new byte[64];int size=0,n;
        while(size<first.length&&(n=input.read(first,size,first.length-size))>0)size+=n;
        return header(first,size);
    }
    public static List<Library> libraries(File apk)throws IOException{
        ArrayList<Library> found=new ArrayList<>();
        try(ZipFile zip=new ZipFile(apk)){
            Enumeration<? extends ZipEntry> entries=zip.entries();
            int examined=0;
            while(entries.hasMoreElements()&&examined++<15000){
                ZipEntry entry=entries.nextElement();
                if(!entry.isDirectory()&&entry.getName().startsWith("lib/")&&
                    entry.getName().endsWith(".so")){
                    if(found.size()>=200)break;
                    try(InputStream in=zip.getInputStream(entry)){
                        found.add(new Library(entry.getName(),inspect(in)));
                    }
                }
            }
        }
        return found;
    }
    public static boolean supported(Elf elf,String[] deviceAbis){
        return elf.valid&&Arrays.asList(deviceAbis).contains(elf.abi);
    }
    public static String report(File apk)throws IOException{
        List<Library> libs=libraries(apk);
        String[] device=Build.SUPPORTED_ABIS;
        StringBuilder out=new StringBuilder();
        out.append("ABI телефона: ").append(Arrays.toString(device)).append("\n");
        if(libs.isEmpty()){
            return out.append("Нативные библиотеки lib/<abi>/*.so не найдены. "+
                "APK может быть полностью Java/Kotlin, а может подгружать код иначе.").toString();
        }
        Set<String> available=new HashSet<>();
        boolean supported=false;
        for(Library lib:libs){
            available.add(lib.elf.abi);
            if(supported(lib.elf,device)&&lib.placementMatches)supported=true;
            out.append("• ").append(lib.path).append("\n  ")
                .append(lib.elf.description()).append(lib.placementMatches?"":" · НЕСООТВЕТСТВИЕ ПУТИ")
                .append("\n");
        }
        out.append("\nДоступные ABI: ").append(available)
            .append("\nСовместимая ABI для телефона: ").append(supported?"есть":"не найдена")
            .append("\n\nВНИМАНИЕ: перекладывание .so в другую папку или "+
                "изменение ELF-заголовка НЕ переводит 32-битный код в 64-битный. "+
                "Нужна настоящая библиотека для указанной архитектуры, собранная из исходников.")
            .append("\nДаже совпадение ABI не гарантирует загрузку: могут отсутствовать "+
                "зависимости или требоваться 16-КиБ ELF-сегменты.");
        return out.toString();
    }
}
