package dev.aster.guard;

import android.os.RemoteException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

/** Executed by Shizuku with shell identity, NOT with Android app permissions. */
public final class ShizukuDiagnosticService extends IExecService.Stub {
    public ShizukuDiagnosticService() {}

    @Override public String inspect(int code)throws RemoteException{
        final String[] args;
        if(code==1)args=new String[]{"ps","-A","-o","PID,NAME,RSS"};
        else if(code==2)args=new String[]{"dumpsys","meminfo","-a"};
        else if(code==3)args=new String[]{"dumpsys","activity","processes"};
        else throw new SecurityException("Команда запрещена");
        Process p=null;
        try{
            p=new ProcessBuilder(args).redirectErrorStream(true).start();
            byte[] buffer=new byte[4096];int total=0;
            ByteArrayOutputStream result=new ByteArrayOutputStream();
            try(InputStream in=p.getInputStream()){
                long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);
                while(System.nanoTime()<deadline&&total<48*1024){
                    if(in.available()==0){
                        try{p.exitValue();break;}
                        catch(IllegalThreadStateException live){
                            Thread.sleep(35);
                            continue;
                        }
                    }
                    int n=in.read(buffer,0,Math.min(buffer.length,48*1024-total));
                    if(n<0)break;
                    result.write(buffer,0,n);total+=n;
                }
            }
            return result.size()==0?"Shizuku не получил данные от Android":result.toString("UTF-8");
        }catch(Exception e){return "Ошибка "+e.getClass().getSimpleName()+": "+e.getMessage();}
        finally{if(p!=null)p.destroy();}
    }
    @Override public void destroy(){System.exit(0);}
}
