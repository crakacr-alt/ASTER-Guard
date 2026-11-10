package dev.aster.guard;

import android.app.AppOpsManager;
import android.app.usage.NetworkStats;
import android.app.usage.NetworkStatsManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.os.Build;
import android.os.Process;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Metadata and OS-maintained usage counters. Does not intercept packets. */
public final class NetworkReader {
    private NetworkReader() {}
    public static final class Connection {
        public String transport="Нет активной сети", privateDns="Неизвестно", proxy="Нет", dns="Нет данных";
        public boolean vpn, metered;
    }
    public static final class Usage {
        public final int uid;
        public String appName;
        public long rx,tx;
        public Usage(int uid, String appName) { this.uid=uid; this.appName=appName; }
    }
    public static Connection connection(Context ctx) {
        Connection out = new Connection();
        ConnectivityManager cm=(ConnectivityManager)ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return out;
        Network active=cm.getActiveNetwork();
        if (active==null) return out;
        NetworkCapabilities cap=cm.getNetworkCapabilities(active);
        if (cap!=null) {
            out.vpn=cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            if (cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) out.transport="Wi-Fi";
            else if (cap.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) out.transport="Мобильная сеть";
            else if (cap.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) out.transport="Ethernet";
            else if (out.vpn) out.transport="VPN";
            else out.transport="Другое соединение";
        }
        out.metered=cm.isActiveNetworkMetered();
        LinkProperties lp=cm.getLinkProperties(active);
        if (lp!=null) {
            StringBuilder dns=new StringBuilder();
            for (InetAddress server:lp.getDnsServers()) {
                if (dns.length()>0) dns.append(", ");
                dns.append(server.getHostAddress());
            }
            if (dns.length()>0) out.dns=dns.toString();
            ProxyInfo proxy=lp.getHttpProxy();
            if (proxy!=null) out.proxy=String.valueOf(proxy.getHost())+":"+proxy.getPort();
            if (Build.VERSION.SDK_INT>=28) {
                out.privateDns=lp.isPrivateDnsActive() ?
                    ("Включён"+(lp.getPrivateDnsServerName()==null?"":" · "+lp.getPrivateDnsServerName()))
                    : "Выключен";
            }
        }
        return out;
    }
    public static boolean hasUsageAccess(Context ctx) {
        AppOpsManager ops=(AppOpsManager)ctx.getSystemService(Context.APP_OPS_SERVICE);
        if (ops==null) return false;
        return ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS,Process.myUid(),ctx.getPackageName())
            == AppOpsManager.MODE_ALLOWED;
    }
    public static List<Usage> last24Hours(Context ctx) throws SecurityException {
        if (!hasUsageAccess(ctx)) throw new SecurityException("Требуется доступ к статистике использования");
        NetworkStatsManager manager=(NetworkStatsManager)ctx.getSystemService(Context.NETWORK_STATS_SERVICE);
        if (manager==null) return Collections.emptyList();
        long now=System.currentTimeMillis(), start=now-24L*60*60*1000;
        Map<Integer,Usage> map=new HashMap<>();
        // Two batched OS queries, not one query per installed app.
        accumulate(manager,ConnectivityManager.TYPE_WIFI,start,now,map);
        accumulate(manager,ConnectivityManager.TYPE_MOBILE,start,now,map);
        PackageManager pm=ctx.getPackageManager();
        List<Usage> out=new ArrayList<>(map.values());
        for (Usage u:out) {
            String[] pkgs=pm.getPackagesForUid(u.uid);
            if (pkgs!=null && pkgs.length>0) {
                try { u.appName=String.valueOf(pm.getApplicationLabel(pm.getApplicationInfo(pkgs[0],0))); }
                catch (Exception ignored) { u.appName=pkgs[0]; }
            }
        }
        Collections.sort(out,new Comparator<Usage>() {
            @Override public int compare(Usage a,Usage b) {
                return Long.compare(b.rx+b.tx,a.rx+a.tx);
            }
        });
        return out;
    }
    private static void accumulate(NetworkStatsManager m,int type,long start,long now,Map<Integer,Usage> map) {
        NetworkStats stats=null;
        try {
            stats=m.queryDetails(type,null,start,now);
            if (stats==null) return;
            NetworkStats.Bucket b=new NetworkStats.Bucket();
            while(stats.hasNextBucket()) {
                stats.getNextBucket(b);
                int uid=b.getUid();
                Usage u=map.get(uid);
                if (u==null) {u=new Usage(uid,"UID "+uid);map.put(uid,u);}
                u.rx+=b.getRxBytes();
                u.tx+=b.getTxBytes();
            }
        } finally {
            if(stats!=null) stats.close();
        }
    }
}
