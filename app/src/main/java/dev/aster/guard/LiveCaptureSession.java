package dev.aster.guard;

import android.content.Intent;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * An intentionally bounded LOCAL listener for PCAPdroid UDP exporter.
 * PCAPdroid is a separately installed, separately authorized packet-forwarding
 * VPN. ASTER itself NEVER establishes a TUN device or changes device routing.
 *
 * Packets are parsed in memory and discarded immediately. Raw payloads and
 * URLs are never persisted. No CA/MITM, packet forwarding, or remote collector.
 */
public final class LiveCaptureSession implements AutoCloseable {
    public static final int PORT=5123;
    private static final long MAX_DURATION_MS=3L*60L*1000L;
    private static final int MAX_FRAMES=35000;
    public static final String CAPTURE_PACKAGE="com.emanuelef.remote_capture";
    public static final String CAPTURE_ACTIVITY="com.emanuelef.remote_capture.activities.CaptureCtrl";
    private final Object lock=new Object();
    private DatagramSocket socket;
    private Thread thread;
    private volatile boolean running;
    private volatile String error="";
    private volatile int discarded;
    private volatile String packageFilter="";
    private final PcapInspector.Report report=new PcapInspector.Report();
    private int link=101;
    private boolean littleEndian=true;
    private final long begunAt=android.os.SystemClock.elapsedRealtime();

    public synchronized void start(String targetPackage)throws IOException {
        if(running)throw new IllegalStateException("Уже запущено");
        if(targetPackage!=null&&!targetPackage.isEmpty()&&
                !targetPackage.matches("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))
            throw new IllegalArgumentException("Неверный пакет приложения");
        packageFilter=targetPackage==null?"":targetPackage;
        socket=new DatagramSocket(PORT, InetAddress.getByName("127.0.0.1"));
        socket.setSoTimeout(1200);
        running=true;
        thread=new Thread(this::readLoop,"ASTER-Live-PCAP");
        thread.setDaemon(true);
        thread.start();
    }
    public boolean isRunning(){return running;}
    public String getError(){return error;}
    public String filter(){return packageFilter;}
    public int dropped(){return discarded;}
    public long ageMs(){return android.os.SystemClock.elapsedRealtime()-begunAt;}

    public static Intent controlIntent(String action,String targetPackage){
        Intent intent=new Intent(Intent.ACTION_VIEW);
        intent.setClassName(CAPTURE_PACKAGE,CAPTURE_ACTIVITY);
        intent.putExtra("action",action);
        if("start".equals(action)){
            intent.putExtra("pcap_dump_mode","udp_exporter");
            intent.putExtra("collector_host","127.0.0.1");
            intent.putExtra("collector_port",PORT);
            intent.putExtra("snaplen",512);      // metadata, not full content
            intent.putExtra("max_pkts_per_flow",16);
            intent.putExtra("max_dump_size",4*1024*1024);
            intent.putExtra("full_payload",false);
            intent.putExtra("dump_extensions",false); // RAW IP; per-app filter is explicit
            intent.putExtra("tls_decryption",false);
            if(targetPackage!=null&&!targetPackage.isEmpty())
                intent.putExtra("app_filter",targetPackage);
        }
        return intent;
    }

    private void readLoop(){
        byte[] payload=new byte[65535];
        DatagramPacket packet=new DatagramPacket(payload,payload.length);
        try{
            while(running && ageMs()<MAX_DURATION_MS){
                synchronized(lock){if(report.packets>=MAX_FRAMES)break;}
                packet.setLength(payload.length);
                try{socket.receive(packet);}
                catch(SocketTimeoutException timeout){continue;}
                if(!packet.getAddress().isLoopbackAddress()){discarded++;continue;}
                int len=packet.getLength();
                if(len==24 && isPcapHeader(payload,len)){
                    littleEndian=(payload[0]&255)==0xd4||(payload[0]&255)==0x4d;
                    int found=read32(payload,20,littleEndian);
                    if(found==1||found==101)link=found;
                    continue;
                }
                int position=0;
                while(position+16<=len){
                    long included=read32(payload,position+8,littleEndian)&0xffffffffL;
                    if(included<0||included>65535||position+16L+included>len){
                        discarded++;break;
                    }
                    synchronized(lock){
                        PcapInspector.observeFrame(payload,position+16,(int)included,link,report);
                    }
                    position+=16+(int)included;
                }
            }
        }catch(IOException e){
            if(running)error=e.toString();
        }finally{
            running=false;
            DatagramSocket s=socket;
            if(s!=null)s.close();
        }
    }
    private static boolean isPcapHeader(byte[] data,int len){
        if(len!=24)return false;
        int a=data[0]&255,b=data[1]&255,c=data[2]&255,d=data[3]&255;
        return (a==0xd4&&b==0xc3&&c==0xb2&&d==0xa1)||
               (a==0xa1&&b==0xb2&&c==0xc3&&d==0xd4)||
               (a==0x4d&&b==0x3c&&c==0xb2&&d==0xa1)||
               (a==0xa1&&b==0xb2&&c==0x3c&&d==0x4d);
    }
    static int read32(byte[] data,int pos,boolean le){
        if(le)return (data[pos]&255)|((data[pos+1]&255)<<8)|
                ((data[pos+2]&255)<<16)|((data[pos+3]&255)<<24);
        return ((data[pos]&255)<<24)|((data[pos+1]&255)<<16)|
                ((data[pos+2]&255)<<8)|(data[pos+3]&255);
    }
    /** Shallow copy: bounded sets/maps contain only metadata, no packet bytes. */
    public PcapInspector.Report snapshot(){
        synchronized(lock){
            PcapInspector.Report s=new PcapInspector.Report();
            s.packets=report.packets;s.ipv4=report.ipv4;s.ipv6=report.ipv6;
            s.tcp=report.tcp;s.udp=report.udp;s.truncated=report.truncated;
            s.endpoints.putAll(report.endpoints);
            s.domains.addAll(report.domains);
            s.hosts.addAll(report.hosts);
            s.note="Источник: PCAPdroid (внешнее приложение). "+
                    (packageFilter.isEmpty()?"Режим всех приложений, нет UID в данных.":("Фильтр приложения: "+packageFilter+". "))+
                    "Указаны назначения пакетов, а не доказанные обращения к вредоносным серверам.";
            return s;
        }
    }
    @Override public synchronized void close(){
        running=false;
        DatagramSocket s=socket;
        if(s!=null)s.close();
        if(thread!=null && Thread.currentThread()!=thread){
            try{thread.join(400);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}
        }
    }
}
