package dev.aster.guard;

import android.app.ActivityManager;
import android.app.NotificationManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.os.StatFs;
import android.os.SystemClock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/** A single cheap OS snapshot. No polling, wakelocks, background tasks or process killing. */
public final class DeviceHealth {
    public static final class Snapshot {
        public int batteryPercent=-1, thermalStatus=-1;
        public float batteryC=Float.NaN;
        public long ramTotal=-1, ramAvailable=-1, storageTotal=-1, storageAvailable=-1, uptimeMs=-1;
        public boolean lowMemory, batterySaver, charging;
        public String patch="Неизвестно", kernel="Недоступно", model="";
        public final List<String> advice=new ArrayList<>();
        public final List<AppActivity> topApps=new ArrayList<>();
    }
    public static final class AppActivity {
        public final String name, pkg;
        public final long foregroundMs;
        public AppActivity(String name,String pkg,long ms){this.name=name;this.pkg=pkg;this.foregroundMs=ms;}
    }
    private DeviceHealth(){}

    public static Snapshot snapshot(Context c){
        Snapshot s=new Snapshot();
        s.model=Build.MANUFACTURER+" "+Build.MODEL;
        s.patch=Build.VERSION.SDK_INT>=23?Build.VERSION.SECURITY_PATCH:"Неизвестно";
        s.kernel=System.getProperty("os.version","Недоступно");
        s.uptimeMs=SystemClock.elapsedRealtime();
        Intent b=c.registerReceiver(null,new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if(b!=null){
            int level=b.getIntExtra(BatteryManager.EXTRA_LEVEL,-1);
            int scale=b.getIntExtra(BatteryManager.EXTRA_SCALE,-1);
            if(level>=0&&scale>0)s.batteryPercent=(int)Math.round(level*100.0/scale);
            int temp=b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE,Integer.MIN_VALUE);
            if(temp!=Integer.MIN_VALUE)s.batteryC=temp/10f;
            int state=b.getIntExtra(BatteryManager.EXTRA_STATUS,-1);
            s.charging=state==BatteryManager.BATTERY_STATUS_CHARGING || state==BatteryManager.BATTERY_STATUS_FULL;
        }
        ActivityManager am=(ActivityManager)c.getSystemService(Context.ACTIVITY_SERVICE);
        if(am!=null){
            ActivityManager.MemoryInfo mem=new ActivityManager.MemoryInfo();
            am.getMemoryInfo(mem);
            s.ramTotal=mem.totalMem;s.ramAvailable=mem.availMem;s.lowMemory=mem.lowMemory;
        }
        StatFs disk=new StatFs(Environment.getDataDirectory().getAbsolutePath());
        s.storageTotal=disk.getTotalBytes();s.storageAvailable=disk.getAvailableBytes();
        PowerManager power=(PowerManager)c.getSystemService(Context.POWER_SERVICE);
        if(power!=null){
            s.batterySaver=power.isPowerSaveMode();
            if(Build.VERSION.SDK_INT>=29)s.thermalStatus=power.getCurrentThermalStatus();
        }

        if(s.lowMemory)s.advice.add("Android сообщает о дефиците ОЗУ. Закройте ненужные тяжёлые приложения вручную; система сама управляет кэшем.");
        if(s.thermalStatus>=PowerManager.THERMAL_STATUS_SEVERE)
            s.advice.add("Тепловое ограничение высокое: снизьте нагрузку, уберите телефон из чехла, прекратите зарядку во время игры.");
        else if(s.thermalStatus>=PowerManager.THERMAL_STATUS_MODERATE)
            s.advice.add("Android сообщил о повышенной тепловой нагрузке. Для игры полезно уменьшить графику или частоту кадров.");
        if(!Float.isNaN(s.batteryC)&&s.batteryC>=45)
            s.advice.add("Аккумулятор нагрет. Это температура батареи, не CPU; избегайте дополнительного нагрева.");
        if(s.storageTotal>0 && s.storageAvailable*100/s.storageTotal<10)
            s.advice.add("На внутреннем хранилище менее 10% свободного места. Удалите ненужные файлы через настройки.");
        if(s.batteryPercent>=0&&s.batteryPercent<20&&!s.charging)
            s.advice.add("Мало заряда батареи: возможно ограничение производительности системой.");
        if(s.batterySaver)s.advice.add("Режим экономии заряда активен и может ограничивать производительность игры.");
        if(s.advice.isEmpty())s.advice.add("Критичных признаков перегрузки по доступным системным показателям не найдено.");
        return s;
    }

    /** Usage access reveals foreground *time*, not per-app CPU/RAM measurements. */
    public static List<AppActivity> foreground24h(Context c) {
        if(!NetworkReader.hasUsageAccess(c))return Collections.emptyList();
        UsageStatsManager mgr=(UsageStatsManager)c.getSystemService(Context.USAGE_STATS_SERVICE);
        if(mgr==null)return Collections.emptyList();
        long end=System.currentTimeMillis();
        List<UsageStats> list=mgr.queryUsageStats(UsageStatsManager.INTERVAL_DAILY,end-86400000L,end);
        if(list==null)return Collections.emptyList();
        List<AppActivity> found=new ArrayList<>();
        for(UsageStats u:list){
            if(u.getTotalTimeInForeground()<1000)continue;
            String name=u.getPackageName();
            try{name=String.valueOf(c.getPackageManager().getApplicationLabel(
                c.getPackageManager().getApplicationInfo(u.getPackageName(),0)));
            }catch(Exception ignored){}
            found.add(new AppActivity(name,u.getPackageName(),u.getTotalTimeInForeground()));
        }
        Collections.sort(found,(a,b)->Long.compare(b.foregroundMs,a.foregroundMs));
        if(found.size()>25)return new ArrayList<>(found.subList(0,25));
        return found;
    }
}
