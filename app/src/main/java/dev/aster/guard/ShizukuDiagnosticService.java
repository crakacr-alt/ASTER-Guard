package dev.aster.guard;

import android.os.RemoteException;
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
            if(p.isAlive())p.destroyForcibly();
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
    @Override public void destroy(){System.exit(0);}
}
