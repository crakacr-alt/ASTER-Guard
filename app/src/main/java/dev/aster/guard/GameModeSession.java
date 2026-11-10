package dev.aster.guard;

import android.app.AlarmManager;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.SystemClock;

/** Inexact one-shot 90-minute DND restoration; no polling, no resident service. */
public final class GameModeSession extends BroadcastReceiver {
    private static final String ACTION="dev.aster.guard.GAME_TIMEOUT";
    private static final long DURATION=90L*60L*1000L;
    private static PendingIntent intent(Context c){
        Intent i=new Intent(c,GameModeSession.class).setAction(ACTION);
        return PendingIntent.getBroadcast(c,2110,i,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
    }
    private static SharedPreferences prefs(Context c){
        return c.getSharedPreferences("GameMode",Context.MODE_PRIVATE);
    }
    public static boolean active(Context c){return prefs(c).getBoolean("enabled",false);}
    public static void start(Context c){
        NotificationManager nm=(NotificationManager)c.getSystemService(Context.NOTIFICATION_SERVICE);
        if(nm==null||!nm.isNotificationPolicyAccessGranted())
            throw new SecurityException("Требуется разрешение «Не беспокоить»");
        SharedPreferences p=prefs(c);
        if(active(c))return;
        int before=nm.getCurrentInterruptionFilter();
        nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_PRIORITY);
        long deadline=SystemClock.elapsedRealtime()+DURATION;
        p.edit().putBoolean("enabled",true).putInt("before",before).putLong("until",deadline).apply();
        AlarmManager manager=(AlarmManager)c.getSystemService(Context.ALARM_SERVICE);
        if(manager!=null){
            // Inexact by design: no exact alarm permission or recurring task.
            manager.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP,deadline,intent(c));
        }
    }
    public static void stop(Context c){
        SharedPreferences p=prefs(c);
        if(!active(c))return;
        NotificationManager nm=(NotificationManager)c.getSystemService(Context.NOTIFICATION_SERVICE);
        if(nm!=null&&nm.isNotificationPolicyAccessGranted()){
            try{
                if(nm.getCurrentInterruptionFilter()==NotificationManager.INTERRUPTION_FILTER_PRIORITY)
                    nm.setInterruptionFilter(p.getInt("before",NotificationManager.INTERRUPTION_FILTER_ALL));
            }catch(Exception ignored){ /* Do not prevent logical session from ending. */ }
        }
        p.edit().putBoolean("enabled",false).remove("until").apply();
        AlarmManager alarm=(AlarmManager)c.getSystemService(Context.ALARM_SERVICE);
        if(alarm!=null)alarm.cancel(intent(c));
    }
    public static void restoreIfExpired(Context c){
        if(active(c)&&SystemClock.elapsedRealtime()>=prefs(c).getLong("until",0))stop(c);
    }
    @Override public void onReceive(Context c,Intent i){
        if(i!=null&&ACTION.equals(i.getAction()))restoreIfExpired(c);
    }
}
