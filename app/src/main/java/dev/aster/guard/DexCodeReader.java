package dev.aster.guard;

import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.Reference;
import org.jf.dexlib2.util.ReferenceUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * On-demand read-only DEX explorer using dexlib2. This displays *real DEX
 * bytecode instructions*, not fabricated Java source or a live debugger.
 * All inputs are from locally installed APKs; no remote upload/exec.
 */
public final class DexCodeReader {
    static final int MAX_DEX_BYTES=64*1024*1024;
    private static final int MAX_CLASSES=35000;
    private static final int MAX_METHOD_LINES=900;
    public static final class Item {
        public final String path, entry, type;
        Item(String path,String entry,String type){this.path=path;this.entry=entry;this.type=type;}
        public String simple(){
            String name=type;
            if(name.startsWith("L")&&name.endsWith(";"))name=name.substring(1,name.length()-1);
            return name.replace('/','.');
        }
    }
    public static final class Index {
        public final List<Item> classes=new ArrayList<>();
        public final List<String> skipped=new ArrayList<>();
        public int dexFiles;
    }
    private String currentPath="",currentEntry="";
    private DexBackedDexFile dex;
    private DexCodeReader(){}
    public static DexCodeReader create(){return new DexCodeReader();}

    public Index index(String[] paths, String appPackage) throws IOException {
        Index result=new Index();
        for(int p=0;p<paths.length&&p<24;p++){
            if(paths[p]==null||paths[p].isEmpty())continue;
            try(ZipFile apk=new ZipFile(paths[p])){
                java.util.Enumeration<? extends ZipEntry> entries=apk.entries();
                int n=0;
                while(entries.hasMoreElements()&&n++<30000){
                    if(Thread.currentThread().isInterrupted())throw new IOException("Отменено");
                    ZipEntry entry=entries.nextElement();
                    if(!entry.getName().matches("classes(?:[0-9]+)?\\.dex"))continue;
                    if(entry.getSize()>MAX_DEX_BYTES){
                        result.skipped.add(entry.getName()+" превышает лимит 64 МБ");continue;
                    }
                    try{
                        DexBackedDexFile df=load(apk,entry);
                        result.dexFiles++;
                        for(ClassDef cls:df.getClasses()){
                            if(result.classes.size()>=MAX_CLASSES){
                                result.skipped.add("Лимит индекса 35000 классов");
                                return sort(result,appPackage);
                            }
                            result.classes.add(new Item(paths[p],entry.getName(),cls.getType()));
                        }
                    }catch(Exception ex){
                        result.skipped.add(entry.getName()+": "+ex.getClass().getSimpleName());
                    }
                }
            }
        }
        return sort(result,appPackage);
    }
    private static Index sort(Index result,String app){
        final String prefix="L"+app.replace('.','/')+"/";
        Collections.sort(result.classes,(a,b)->{
            boolean ownA=a.type.startsWith(prefix),ownB=b.type.startsWith(prefix);
            if(ownA!=ownB)return ownA?-1:1;
            return a.type.compareToIgnoreCase(b.type);
        });
        return result;
    }
    public static DexBackedDexFile load(ZipFile apk, ZipEntry entry)throws IOException {
        if(entry.getSize()>MAX_DEX_BYTES)throw new IOException("DEX превышает 64 МБ");
        ByteArrayOutputStream out=new ByteArrayOutputStream(128*1024);
        try(InputStream in=apk.getInputStream(entry)){
            byte[] chunk=new byte[32*1024];int total=0,n;
            while((n=in.read(chunk))!=-1){
                total+=n;
                if(total>MAX_DEX_BYTES)throw new IOException("DEX слишком большой");
                out.write(chunk,0,n);
                if(Thread.currentThread().isInterrupted())throw new IOException("Отменено");
            }
        }
        return new DexBackedDexFile(Opcodes.forApi(35),out.toByteArray());
    }
    private DexBackedDexFile selected(Item item)throws IOException {
        if(dex!=null&&item.path.equals(currentPath)&&item.entry.equals(currentEntry))return dex;
        dex=null;
        try(ZipFile apk=new ZipFile(item.path)){
            ZipEntry entry=apk.getEntry(item.entry);
            if(entry==null)throw new IOException("DEX не найден");
            DexBackedDexFile loaded=load(apk,entry);
            dex=loaded;currentPath=item.path;currentEntry=item.entry;
            return loaded;
        }
    }
    public ClassDef getClassDef(Item item)throws IOException {
        for(ClassDef clazz:selected(item).getClasses()){
            if(clazz.getType().equals(item.type))return clazz;
        }
        throw new IOException("Класс отсутствует");
    }
    public List<Method> methods(Item item)throws IOException {
        ArrayList<Method> methods=new ArrayList<>();
        for(Method m:getClassDef(item).getMethods())methods.add(m);
        Collections.sort(methods,Comparator.comparing(Method::getName));
        return methods;
    }
    public static String methodName(Method m){
        StringBuilder b=new StringBuilder(m.getName()).append('(');
        for(CharSequence p:m.getParameterTypes())b.append(shortType(p.toString())).append(',');
        if(b.charAt(b.length()-1)==',')b.setLength(b.length()-1);
        return b.append(") : ").append(shortType(m.getReturnType())).toString();
    }
    static String shortType(String value){
        int array=0;
        while(value.startsWith("[")){array++;value=value.substring(1);}
        if(value.startsWith("L")&&value.endsWith(";")){
            value=value.substring(1,value.length()-1);
            value=value.substring(value.lastIndexOf('/')+1);
        }else{
            switch(value){
                case "V":value="void";break;
                case "I":value="int";break;
                case "Z":value="boolean";break;
                case "J":value="long";break;
                case "F":value="float";break;
                case "D":value="double";break;
                case "B":value="byte";break;
                case "S":value="short";break;
                case "C":value="char";break;
            }
        }
        for(int i=0;i<array;i++)value+="[]";
        return value;
    }
    public String disassemble(Item item, Method selected)throws IOException {
        ClassDef owner=getClassDef(item);
        Method target=null;
        for(Method m:owner.getMethods()){
            if(m.getName().equals(selected.getName())&&
               m.getParameterTypes().equals(selected.getParameterTypes())&&
               m.getReturnType().equals(selected.getReturnType())){
                target=m;break;
            }
        }
        if(target==null)throw new IOException("Метод не найден в DEX");
        StringBuilder result=new StringBuilder(10000);
        result.append("# ASTER Guard · DEX / Smali-like viewer\n")
            .append("# Только чтение, НЕ Java-декомпиляция и НЕ live debugger\n")
            .append("# APK: ").append(item.path.substring(item.path.lastIndexOf('/')+1)).append("\n")
            .append("# DEX: ").append(item.entry).append("\n\n")
            .append(".class ").append(item.type).append("\n");
        if(owner.getSuperclass()!=null)result.append(".super ").append(owner.getSuperclass()).append("\n");
        result.append("\n.method ").append(target.getName()).append('(');
        for(CharSequence param:target.getParameterTypes())result.append(param);
        result.append(')').append(target.getReturnType()).append('\n');
        MethodImplementation impl=target.getImplementation();
        if(impl==null){
            result.append("    # Abstract/native method: нет исполняемого DEX-тела\n.end method");
            return result.toString();
        }
        result.append("    .registers ").append(impl.getRegisterCount()).append("\n\n");
        int address=0,count=0;
        try{
            for(Instruction ins:impl.getInstructions()){
                if(Thread.currentThread().isInterrupted())throw new IOException("Отменено");
                if(count++>=MAX_METHOD_LINES){
                    result.append("    # Обрезано после 900 инструкций для защиты интерфейса\n");break;
                }
                result.append(String.format(java.util.Locale.ROOT,"    %04x: ",address));
                result.append(format(ins)).append('\n');
                address+=ins.getCodeUnits();
                if(result.length()>105000){
                    result.append("    # Вывод ограничен 105 КБ\n");break;
                }
            }
        }catch(RuntimeException ex){
            result.append("    # Ошибка чтения инструкции: ").append(ex.getClass().getSimpleName()).append("\n");
        }
        result.append(".end method\n");
        return result.toString();
    }

    static String format(Instruction ins){
        StringBuilder out=new StringBuilder(ins.getOpcode().name);
        ArrayList<String> operands=new ArrayList<>();
        if(ins instanceof FiveRegisterInstruction){
            FiveRegisterInstruction x=(FiveRegisterInstruction)ins;
            int[] rs={x.getRegisterC(),x.getRegisterD(),x.getRegisterE(),x.getRegisterF(),x.getRegisterG()};
            int count=x instanceof VariableRegisterInstruction ? ((VariableRegisterInstruction)x).getRegisterCount():5;
            StringBuilder tmp=new StringBuilder("{");
            for(int i=0;i<Math.min(5,count);i++){
                if(i>0)tmp.append(", ");
                tmp.append("v").append(rs[i]);
            }
            operands.add(tmp.append('}').toString());
        }else if(ins instanceof RegisterRangeInstruction){
            RegisterRangeInstruction x=(RegisterRangeInstruction)ins;
            int n=x instanceof VariableRegisterInstruction?((VariableRegisterInstruction)x).getRegisterCount():0;
            operands.add("{v"+x.getStartRegister()+" .. v"+(x.getStartRegister()+Math.max(0,n-1))+"}");
        }else if(ins instanceof ThreeRegisterInstruction){
            ThreeRegisterInstruction x=(ThreeRegisterInstruction)ins;
            operands.add("v"+x.getRegisterA());operands.add("v"+x.getRegisterB());operands.add("v"+x.getRegisterC());
        }else if(ins instanceof TwoRegisterInstruction){
            TwoRegisterInstruction x=(TwoRegisterInstruction)ins;
            operands.add("v"+x.getRegisterA());operands.add("v"+x.getRegisterB());
        }else if(ins instanceof OneRegisterInstruction){
            operands.add("v"+((OneRegisterInstruction)ins).getRegisterA());
        }
        if(ins instanceof ReferenceInstruction){
            Reference ref=((ReferenceInstruction)ins).getReference();
            try{operands.add(ReferenceUtil.getReferenceString(ref));}
            catch(RuntimeException e){operands.add("<нечитаемая ссылка>");}
        }
        if(ins instanceof DualReferenceInstruction){
            try{operands.add(ReferenceUtil.getReferenceString(((DualReferenceInstruction)ins).getReference2()));}
            catch(RuntimeException e){operands.add("<нечитаемая ссылка>");}
        }
        if(ins instanceof NarrowLiteralInstruction)operands.add("#"+((NarrowLiteralInstruction)ins).getNarrowLiteral());
        else if(ins instanceof WideLiteralInstruction)operands.add("#"+((WideLiteralInstruction)ins).getWideLiteral());
        if(ins instanceof OffsetInstruction)operands.add(String.format(java.util.Locale.ROOT,"offset %+#x",((OffsetInstruction)ins).getCodeOffset()));
        if(!operands.isEmpty())out.append(" ").append(android.text.TextUtils.join(", ",operands));
        return out.toString();
    }
}
