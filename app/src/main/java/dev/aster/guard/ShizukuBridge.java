package dev.aster.guard;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.os.IBinder;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import rikka.shizuku.Shizuku;

/** Explicit-consent Shizuku bridge with server-side fixed allowlisted operations. */
public final class ShizukuBridge {
    public static final int REQUEST_CODE=2081;
    private ShizukuBridge(){}
    public static boolean available(){
        try{return Shizuku.pingBinder();}catch(Throwable t){return false;}
    }
    public static boolean authorized(){
        try{return available()&&!Shizuku.isPreV11()&&
            Shizuku.checkSelfPermission()==PackageManager.PERMISSION_GRANTED;}
        catch(Throwable t){return false;}
    }
    public static String status(){
        if(!available())return "Shizuku не запущен / не установлен";
        if(!authorized())return "Shizuku запущен: требуется разрешение ASTER";
        return "Shizuku подключён: разрешение ADB/shell предоставлено";
    }
    public static String diagnostics(Context c,String type)throws Exception{
        final int op;
        switch(type){
            case "processes":op=1;break;
            case "memory":op=2;break;
            case "activity":op=3;break;
            case "cpu":op=4;break;
            default:throw new IllegalArgumentException("Операция не разрешена");
        }
        return execute(c,op,null);
    }
    public static String packageAction(Context c,String pkg,int op)throws Exception{
        if(op<10||op>14)throw new SecurityException("Операция запрещена");
        validate(c,pkg,op==14);
        return execute(c,op,pkg);
    }
    private static final java.util.Set<String> ALLOWED_PRIVACY_OPS=
        new java.util.HashSet<>(java.util.Arrays.asList(
            "FINE_LOCATION","COARSE_LOCATION","READ_CONTACTS","READ_CALL_LOG",
            "READ_SMS","CAMERA","RECORD_AUDIO"));
    public static String setPrivacyOp(Context c,String pkg,String op,boolean deny)throws Exception{
        if(!ALLOWED_PRIVACY_OPS.contains(op))throw new SecurityException("AppOps не разрешён: "+op);
        validate(c,pkg,true);
        if(!authorized())throw new SecurityException("Shizuku не разрешён");
        return executeOp(c,pkg,op,deny);
    }
    private static String executeOp(Context context,String pkg,String op,boolean deny)throws Exception{
        final CountDownLatch ready=new CountDownLatch(1);
        final AtomicReference<IExecService> ref=new AtomicReference<>();
        ServiceConnection conn=new ServiceConnection(){
            @Override public void onServiceConnected(ComponentName name,IBinder binder){
                ref.set(IExecService.Stub.asInterface(binder));ready.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name){ref.set(null);ready.countDown();}
        };
        Shizuku.UserServiceArgs args=new Shizuku.UserServiceArgs(
            new ComponentName(context.getPackageName(),ShizukuDiagnosticService.class.getName()))
            .daemon(false).version(3).processNameSuffix("inspector");
        Shizuku.bindUserService(args,conn);
        try{
            if(!ready.await(9,TimeUnit.SECONDS)||ref.get()==null)
                throw new IllegalStateException("Служба Shizuku недоступна");
            return ref.get().setPrivacyOp(pkg,op,deny);
        }finally{
            try{Shizuku.unbindUserService(args,conn,true);}catch(Throwable ignored){}
        }
    }
    private static void validate(Context c,String pkg,boolean mutating)throws Exception{
        if(pkg==null||!pkg.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+"))
            throw new SecurityException("Неверное имя приложения");
        if(mutating){
            if(pkg.equals(c.getPackageName()))throw new SecurityException("Нельзя остановить ASTER");
            ApplicationInfo info=c.getPackageManager().getApplicationInfo(pkg,0);
            if((info.flags&(ApplicationInfo.FLAG_SYSTEM|ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))!=0)
                throw new SecurityException("Системные приложения нельзя остановить через ASTER");
        }
    }
    private static String execute(Context context,int code,String pkg)throws Exception{
        if(!authorized())throw new SecurityException("Разрешите доступ Shizuku в его приложении");
        final CountDownLatch ready=new CountDownLatch(1);
        final AtomicReference<IExecService> ref=new AtomicReference<>();
        ServiceConnection connection=new ServiceConnection(){
            @Override public void onServiceConnected(ComponentName name,IBinder binder){
                ref.set(IExecService.Stub.asInterface(binder));ready.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name){
                ref.set(null);ready.countDown();
            }
        };
        Shizuku.UserServiceArgs args=new Shizuku.UserServiceArgs(
            new ComponentName(context.getPackageName(),ShizukuDiagnosticService.class.getName()))
            .daemon(false).version(2).processNameSuffix("inspector");
        Shizuku.bindUserService(args,connection);
        try{
            if(!ready.await(9,TimeUnit.SECONDS)||ref.get()==null)
                throw new IllegalStateException("Служба Shizuku не подключилась (9 секунд)");
            return pkg==null?ref.get().inspect(code):ref.get().inspectPackage(code,pkg);
        }finally{
            try{Shizuku.unbindUserService(args,connection,true);}catch(Throwable ignored){}
        }
    }
}
