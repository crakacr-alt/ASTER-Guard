package dev.aster.guard;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.IBinder;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import rikka.shizuku.Shizuku;

/**
 * Shizuku user service is spawned only after an explicitly authorized action.
 * Never executes free-form commands from a UI/user-provided string.
 */
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
        return "Shizuku подключён, разрешение предоставлено (ADB/shell не равно root)";
    }
    public static String diagnostics(Context context,String type)throws Exception {
        if(!authorized())throw new SecurityException("Сначала разрешите доступ Shizuku");
        final int code;
        switch(type){
            case "processes":code=1;break;
            case "memory":code=2;break;
            case "activity":code=3;break;
            default:throw new IllegalArgumentException("Неизвестная диагностика");
        }
        final CountDownLatch ready=new CountDownLatch(1);
        final AtomicReference<IExecService> ref=new AtomicReference<>();
        ServiceConnection conn=new ServiceConnection(){
            @Override public void onServiceConnected(ComponentName name,IBinder binder) {
                ref.set(IExecService.Stub.asInterface(binder));ready.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name) {
                ref.set(null);ready.countDown();
            }
        };
        Shizuku.UserServiceArgs args=new Shizuku.UserServiceArgs(
            new ComponentName(context.getPackageName(),ShizukuDiagnosticService.class.getName()))
            .daemon(false).version(1).processNameSuffix("inspector");
        Shizuku.bindUserService(args,conn);
        try{
            if(!ready.await(8,TimeUnit.SECONDS)||ref.get()==null)
                throw new IllegalStateException("Служба Shizuku не ответила в течение 8 секунд");
            return ref.get().inspect(code);
        }finally{
            try{Shizuku.unbindUserService(args,conn,true);}catch(Throwable ignored){}
        }
    }
}
