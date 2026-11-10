package dev.aster.guard;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Offline PCAP parser. Import a capture made in an authorized environment.
 * Extracts destination IP:port, cleartext DNS and HTTP Host, and TLS SNI when
 * a complete ClientHello appears in one TCP segment. Does not decrypt TLS.
 * No capture service, no VPN route hijack and no app attribution from a pcap.
 */
public final class PcapInspector {
    private static final int MAX_BYTES=12*1024*1024,MAX_PACKETS=55000;
    public static final class Report {
        public int packets,ipv4,ipv6,tcp,udp,truncated;
        public final Map<String,Integer> endpoints=new LinkedHashMap<>();
        public final Set<String> domains=new LinkedHashSet<>();
        public final Set<String> hosts=new LinkedHashSet<>();
        public String note="";
    }
    private PcapInspector(){}
    public static Report parse(InputStream input)throws IOException{
        ByteArrayOutputStream mem=new ByteArrayOutputStream(8192);
        byte[] b=new byte[32768];int total=0,n;
        while((n=input.read(b))!=-1){
            total+=n;if(total>MAX_BYTES)throw new IOException("PCAP больше 12 МБ — экспортируйте короткий фрагмент");
            mem.write(b,0,n);
            if(Thread.currentThread().isInterrupted())throw new IOException("Отмена проверки");
        }
        return parseBytes(mem.toByteArray());
    }
    static Report parseBytes(byte[] data)throws IOException{
        if(data.length<24)throw new IOException("Недостаточно данных PCAP");
        boolean le;
        int a=data[0]&255,b=data[1]&255,c=data[2]&255,d=data[3]&255;
        if((a==0xd4&&b==0xc3&&c==0xb2&&d==0xa1)||(a==0x4d&&b==0x3c&&c==0xb2&&d==0xa1))le=true;
        else if((a==0xa1&&b==0xb2&&c==0xc3&&d==0xd4)||(a==0xa1&&b==0xb2&&c==0x3c&&d==0x4d))le=false;
        else throw new IOException("Поддерживается обычный PCAP (не pcapng)");
        int link=read32(data,20,le);
        if(link!=1&&link!=101)throw new IOException("Неизвестный тип канала PCAP: "+link+" (нужен Ethernet или Raw IP)");
        Report out=new Report();int at=24;
        while(at+16<=data.length && out.packets<MAX_PACKETS){
            long included=read32(data,at+8,le)&0xffffffffL;
            if(included<0||included>MAX_BYTES||at+16L+included>data.length){
                out.truncated++;break;
            }
            int start=at+16, len=(int)included;
            out.packets++;readPacket(data,start,len,link,out);
            at=start+len;
            if(Thread.currentThread().isInterrupted())throw new IOException("Отмена проверки");
        }
        out.note="PCAP не содержит UID приложения; IP и домены не доказывают злонамеренность. " +
            "DNS, HTTP и TLS SNI видны только если присутствуют открытым текстом. " +
            "QUIC, DoH, ECH и фрагментация могут скрывать домены.";
        return out;
    }

    /**
     * Observe one complete IP/Ethernet frame from a trusted local capture
     * transport, without buffering original payload bytes.
     * A caller never stores plaintext from packets to disk.
     */
    public static void observeFrame(byte[] bytes,int offset,int length,int link,Report report){
        if(bytes==null||report==null||offset<0||length<0||
           (long)offset+length>bytes.length||length>65535||
           (link!=1&&link!=101)) {
            if(report!=null)report.truncated++;
            return;
        }
        report.packets++;
        readPacket(bytes,offset,length,link,report);
    }

    private static void readPacket(byte[] b,int off,int len,int link,Report r){
        int pos=off,end=off+len;
        int family=0;
        if(link==1){
            if(len<14)return;
            int eth=u16(b,off+12);pos=off+14;
            if(eth==0x8100 && pos+4<=end){eth=u16(b,pos+2);pos+=4;}
            if(eth==0x0800)family=4;
            else if(eth==0x86dd)family=6;
        } else if(pos<end)family=(b[pos]>>>4);
        if(family==4){
            if(pos+20>end)return;
            int headerLen=(b[pos]&15)*4;
            if(headerLen<20||pos+headerLen>end)return;
            int protocol=b[pos+9]&255;
            // Ignore fragments after the first one.
            if((u16(b,pos+6)&0x1fff)!=0)return;
            String destination=ipv4(b,pos+16);
            r.ipv4++;
            transport(b,pos+headerLen,end,protocol,destination,r);
        }else if(family==6){
            if(pos+40>end)return;
            int next=b[pos+6]&255;
            if(next!=6&&next!=17)return; // Extensions need separate handling.
            String destination=ipv6(b,pos+24);
            r.ipv6++;
            transport(b,pos+40,end,next,destination,r);
        }
    }
    private static void transport(byte[] b,int pos,int end,int proto,String ip,Report out){
        if(proto!=6&&proto!=17)return;
        if(pos+8>end)return;
        int sourcePort=u16(b,pos),destPort=u16(b,pos+2);
        if(out.endpoints.size()<200){
            String key=ip+":"+destPort+" / "+(proto==6?"TCP":"UDP");
            out.endpoints.put(key,out.endpoints.containsKey(key)?out.endpoints.get(key)+1:1);
        }
        if(proto==17){
            out.udp++;
            if((sourcePort==53||destPort==53)&&pos+20<=end&&out.domains.size()<70){
                String domain=dnsQuestion(b,pos+8,end);
                if(domain!=null)out.domains.add(domain);
            }
        }else if(proto==6){
            out.tcp++;
            if(pos+20>end)return;
            int tcpHeader=((b[pos+12]>>4)&15)*4;
            int data=pos+tcpHeader;
            if(data>=end||tcpHeader<20)return;
            if((sourcePort==443||destPort==443)&&out.domains.size()<70){
                String sni=tlsSni(b,data,end);
                if(sni!=null)out.domains.add(sni);
            }
            if((sourcePort==80||destPort==80||sourcePort==8080||destPort==8080)
                &&out.hosts.size()<40){
                String host=httpHost(b,data,end);
                if(host!=null)out.hosts.add(host);
            }
        }
    }
    private static String dnsQuestion(byte[] b,int start,int end){
        if(start+12>end)return null;
        int count=u16(b,start+4);
        if(count==0)return null;
        int p=start+12,segments=0;
        StringBuilder sb=new StringBuilder();
        while(p<end&&segments++<20){
            int n=b[p++]&255;
            if(n==0)break;
            if(n>63||p+n>end)return null;
            if(sb.length()>0)sb.append('.');
            for(int i=0;i<n;i++){
                char c=(char)(b[p++]&255);
                if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')
                    sb.append(Character.toLowerCase(c));
                else return null;
            }
        }
        return sb.length()>2?sb.toString():null;
    }
    private static String httpHost(byte[] b,int start,int end){
        int size=Math.min(1600,end-start);
        if(size<8)return null;
        String s=new String(b,start,size,StandardCharsets.ISO_8859_1);
        int at=s.indexOf("\r\nHost:");
        if(at<0)at=s.indexOf("\r\nhost:");
        if(at<0)return null;
        int from=at+7,to=s.indexOf('\r',from);
        if(to<0||to-from>200)return null;
        String host=s.substring(from,to).trim();
        return host.matches("[a-zA-Z0-9.-]{2,190}(:[0-9]{2,5})?")?host:null;
    }
    private static String tlsSni(byte[] b,int at,int end){
        // One complete TLS record with a ClientHello handshake.
        if(at+9>end||(b[at]&255)!=22)return null;
        int record=u16(b,at+3);
        if(at+5+record>end||(b[at+5]&255)!=1)return null;
        int p=at+9;
        if(p+34>end)return null;
        p+=34; // TLS legacy_version + random
        if(p>=end)return null;
        int session=b[p++]&255;p+=session;
        if(p+2>end)return null;
        int ciphers=u16(b,p);p+=2+ciphers;
        if(p>=end)return null;
        int compression=b[p++]&255;p+=compression;
        if(p+2>end)return null;
        int extBytes=u16(b,p);p+=2;
        int limit=Math.min(end,p+extBytes);
        while(p+4<=limit){
            int type=u16(b,p),len=u16(b,p+2);p+=4;
            if(p+len>limit)return null;
            if(type==0&&len>=5){
                int nameLen=u16(b,p+3);
                if((b[p+2]&255)==0&&nameLen>2&&nameLen<=190&&p+5+nameLen<=limit){
                    String host=new String(b,p+5,nameLen,StandardCharsets.US_ASCII).toLowerCase(java.util.Locale.ROOT);
                    if(host.matches("[a-z0-9.-]{3,190}"))return host;
                }
            }
            p+=len;
        }
        return null;
    }
    private static String ipv4(byte[] b,int p){
        return (b[p]&255)+"."+(b[p+1]&255)+"."+(b[p+2]&255)+"."+(b[p+3]&255);
    }
    private static String ipv6(byte[] b,int p){
        try{
            byte[] raw=new byte[16];
            System.arraycopy(b,p,raw,0,16);
            return "["+InetAddress.getByAddress(raw).getHostAddress()+"]";
        }catch(Exception ignored){return "[IPv6]";}
    }
    private static int u16(byte[] b,int p){return ((b[p]&255)<<8)|(b[p+1]&255);}
    private static int read32(byte[] b,int p,boolean le){
        if(le)return (b[p]&255)|((b[p+1]&255)<<8)|((b[p+2]&255)<<16)|((b[p+3]&255)<<24);
        return ((b[p]&255)<<24)|((b[p+1]&255)<<16)|((b[p+2]&255)<<8)|(b[p+3]&255);
    }
}
