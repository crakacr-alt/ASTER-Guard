package dev.aster.guard;

import android.os.RemoteException;
import android.os.ParcelFileDescriptor;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Shizuku user service, executed as shell/adb (not root by assumption).
 * Only fixed command templates are permitted. No free-form command execution.
 */
public final class ShizukuDiagnosticService extends IExecService.Stub {
    public ShizukuDiagnosticService(){}

    @Override public String inspect(int code)throws RemoteException {
        final String[] args;
        switch(code){
            case 1:args=new String[]{"ps","-A","-o","PID,NAME,RSS"};break;
            case 2:args=new String[]{"dumpsys","meminfo","-a"};break;
            case 3:args=new String[]{"dumpsys","activity","processes"};break;
            case 4:args=new String[]{"top","-b","-n","1","-m","60"};break;
            default:throw new SecurityException("Неизвестный код операции");
        }
        return execute(args);
    }
    @Override public String inspectPackage(int code,String pkg)throws RemoteException{
        checkPackageName(pkg);
        switch(code){
            case 10:return execute(new String[]{"dumpsys","package",pkg});
            case 11:return execute(new String[]{"cmd","appops","get",pkg});
            case 12:return execute(new String[]{"dumpsys","meminfo",pkg});
            case 13:return execute(new String[]{"pm","path",pkg});
            case 14:
                if("dev.aster.guard".equals(pkg))
                    throw new SecurityException("Нельзя остановить ASTER");
                if(!isThirdParty(pkg))
                    throw new SecurityException("Только сторонние приложения; системные защищены");
                return execute(new String[]{"am","force-stop",pkg});
            default:throw new SecurityException("Операция запрещена");
        }
    }
    private static final java.util.Set<String> ALLOWED_OPS=
        new java.util.HashSet<>(java.util.Arrays.asList(
            "FINE_LOCATION","COARSE_LOCATION","READ_CONTACTS","READ_CALL_LOG",
            "READ_SMS","CAMERA","RECORD_AUDIO"));
    @Override public String setPrivacyOp(String pkg,String op,boolean deny)throws RemoteException{
        checkPackageName(pkg);
        if(!ALLOWED_OPS.contains(op))throw new SecurityException("AppOps запрещён");
        if("dev.aster.guard".equals(pkg)||!isThirdParty(pkg))
            throw new SecurityException("Нельзя изменять ASTER или системные приложения");
        // One narrowly scoped action. No arbitrary shell, batch changes or privilege grants.
        return execute(new String[]{"cmd","appops","set",pkg,op,deny?"ignore":"default"});
    }
    private static void checkPackageName(String value){
        if(value==null||value.length()>180||
            !value.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+"))
            throw new SecurityException("Некорректный идентификатор приложения");
    }
    private static boolean isThirdParty(String pkg){
        String list=execute(new String[]{"pm","list","packages","-3"});
        for(String line:list.split("\\r?\\n"))
            if(line.trim().equals("package:"+pkg))return true;
        return false;
    }
    private static String execute(String[] args){
        Process p=null;
        try{
            p=new ProcessBuilder(args).redirectErrorStream(true).start();
            // Bound process time and captured bytes; process output is untrusted text.
            ByteArrayOutputStream result=new ByteArrayOutputStream();
            byte[] buffer=new byte[2048];
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
            try(InputStream in=p.getInputStream()){
                while(System.nanoTime()<deadline&&result.size()<48*1024){
                    int ready=in.available();
                    if(ready<=0){
                        try{p.exitValue();break;}
                        catch(IllegalThreadStateException stillRunning){Thread.sleep(25);continue;}
                    }
                    int n=in.read(buffer,0,Math.min(buffer.length,Math.min(ready,48*1024-result.size())));
                    if(n<0)break;
                    result.write(buffer,0,n);
                }
            }
            // Process.destroy() is supported from API 1; minSdk is 24.
            p.destroy();
            String output=result.toString("UTF-8");
            if(output.isEmpty()){
                try{
                    int exit=p.waitFor();
                    if(exit==0)return "Команда завершена успешно, текста нет.";
                }catch(Exception ignored){}
                return "Система отказала в доступе или не вернула данных";
            }
            return output;
        }catch(Exception e){
            return "Команда не выполнена: "+e.getClass().getSimpleName()+": "+e.getMessage();
        }finally{
            if(p!=null){p.destroy();}
        }
    }
    /**
     * Installs a bounded user-selected APK via the shell UID without giving the
     * shell permission to read ASTER's private cache paths.
     * The source FD is passed through AIDL; no arbitrary filesystem or command access.
     */
    @Override public String installApk(ParcelFileDescriptor content,long size,
                                         boolean bypassLowTarget,boolean testOnly)throws RemoteException{
        if(content==null||size<4||size>96L*1024*1024)
            throw new SecurityException("APK должен быть от 4 байт до 96 МиБ");
        java.util.ArrayList<String> args=new java.util.ArrayList<>();
        args.add("pm");args.add("install");args.add("-r");
        if(bypassLowTarget)args.add("--bypass-low-target-sdk-block");
        if(testOnly)args.add("-t");
        args.add("-S");args.add(Long.toString(size));args.add("-");
        Process process=null;
        try(ParcelFileDescriptor.AutoCloseInputStream in =
                new ParcelFileDescriptor.AutoCloseInputStream(content)){
            process=new ProcessBuilder(args).redirectErrorStream(true).start();
            byte[] buffer=new byte[32768];
            long remaining=size;
            try(java.io.OutputStream out=process.getOutputStream()){
                while(remaining>0){
                    int len=in.read(buffer,0,(int)Math.min(buffer.length,remaining));
                    if(len<0)throw new java.io.IOException("Источник APK обрезан");
                    out.write(buffer,0,len);
                    remaining-=len;
                }
            }
            boolean finished=false;
            if(android.os.Build.VERSION.SDK_INT>=26){
                finished=process.waitFor(70,TimeUnit.SECONDS);
            }else{
                long deadline=android.os.SystemClock.elapsedRealtime()+70000L;
                while(android.os.SystemClock.elapsedRealtime()<deadline){
                    try{
                        process.exitValue();
                        finished=true;break;
                    }catch(IllegalThreadStateException stillRunning){
                        Thread.sleep(75);
                    }
                }
            }
            if(!finished){
                process.destroy();
                return "INSTALL_TIMEOUT: установка превысила 70 секунд.";
            }
            ByteArrayOutputStream result=new ByteArrayOutputStream();
            try(InputStream output=process.getInputStream()){
                int n;
                while((n=output.read(buffer))>0&&result.size()<16000)
                    result.write(buffer,0,Math.min(n,16000-result.size()));
            }
            String text=result.toString("UTF-8").trim();
            return "Exit "+process.exitValue()+": "+(text.isEmpty()?"Нет вывода":text);
        }catch(Exception error){
            if(process!=null)process.destroy();
            return "INSTALL_ERROR: "+error.getClass().getSimpleName()+": "+error.getMessage();
        }finally{
            if(process!=null)process.destroy();
        }
    }
    @Override public void destroy(){System.exit(0);}
}
