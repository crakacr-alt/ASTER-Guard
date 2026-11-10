package dev.aster.guard;

import android.content.pm.PackageManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;
import rikka.shizuku.Shizuku;

/** Optional, explicit-consent Shizuku integration. Never escalates privilege silently. */
public final class ShizukuBridge {
    public static final int REQUEST_CODE=2081;
    private ShizukuBridge(){}
    public static boolean available(){
        try{return Shizuku.pingBinder();}catch(Throwable t){return false;}
    }
    public static boolean authorized(){
        try{return available() && !Shizuku.isPreV11() &&
                Shizuku.checkSelfPermission()==PackageManager.PERMISSION_GRANTED;}
        catch(Throwable t){return false;}
    }
    public static String status(){
        if(!available())return "Shizuku не подключён — установите приложение и запустите сервер";
        if(!authorized())return "Shizuku запущен, разрешение ASTER Guard не предоставлено";
        return "Shizuku подключён, доступ разрешён (права shell/ADB, не обязательно root)";
    }
    /**
     * Reads only allowlisted, non-mutating diagnostics. Captures at most 48KiB
     * with a hard 4s process timeout. No caller-supplied shell commands.
     */
    @SuppressWarnings("deprecation")
    public static String diagnostics(String type)throws Exception {
        if(!authorized())throw new SecurityException("Сначала разрешите доступ Shizuku");
        final String[] args;
        switch(type){
            case "processes": args=new String[]{"ps","-A","-o","PID,NAME,RSS"}; break;
            case "memory": args=new String[]{"dumpsys","meminfo","-a"}; break;
            case "activity": args=new String[]{"dumpsys","activity","processes"}; break;
            default:throw new IllegalArgumentException("Неизвестная диагностическая команда");
        }
        Process p=Shizuku.newProcess(args,null,null);
        try{
            ByteArrayOutputStream output=new ByteArrayOutputStream();
            InputStream in=p.getInputStream();
            byte[] buf=new byte[2048];int count=0;
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);
            while(count<48*1024&&System.nanoTime()<deadline){
                if(in.available()==0){
                    if(!p.isAlive())break;
                    Thread.sleep(30);
                    continue;
                }
                int n=in.read(buf,0,Math.min(buf.length,48*1024-count));
                if(n<0)break;
                output.write(buf,0,n);count+=n;
            }
            if(p.isAlive())p.destroy();
            String result=output.toString("UTF-8");
            return result.isEmpty()?"Система не вернула данных или запретила команду":result;
        }finally{p.destroy();}
    }
}
