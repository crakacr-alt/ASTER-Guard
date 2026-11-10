package dev.aster.guard;

import android.content.Context;
import android.content.pm.PackageInfo;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONObject;

/** One HTTPS request on launch, no scheduled background work and no self-install. */
public final class UpdateChecker {
    public static final String API="https://api.github.com/repos/crakacr-alt/ASTER-Guard/releases?per_page=10";
    public static final class Update {
        public final String version,url;
        public Update(String version,String url){this.version=version;this.url=url;}
    }
    private UpdateChecker(){}

    public static Update check(Context c)throws Exception{
        String current=c.getPackageManager().getPackageInfo(c.getPackageName(),0).versionName;
        HttpURLConnection conn=(HttpURLConnection)new URL(API).openConnection();
        conn.setConnectTimeout(5000);conn.setReadTimeout(5000);
        conn.setRequestProperty("Accept","application/vnd.github+json");
        conn.setRequestProperty("User-Agent","ASTER-Guard-Android");
        try{
            if(conn.getResponseCode()!=200)throw new IllegalStateException("GitHub HTTP "+conn.getResponseCode());
            ByteArrayOutputStream result=new ByteArrayOutputStream();
            try(InputStream in=conn.getInputStream()){
                byte[] b=new byte[4096];int n,read=0;
                while((n=in.read(b))!=-1){
                    read+=n;if(read>384*1024)throw new IllegalStateException("Слишком большой ответ GitHub");
                    result.write(b,0,n);
                }
            }
            JSONArray releases=new JSONArray(result.toString("UTF-8"));
            Update best=null;
            for(int i=0;i<releases.length();i++){
                JSONObject r=releases.getJSONObject(i);
                if(r.optBoolean("draft"))continue;
                String tag=r.optString("tag_name","");
                if(!tag.matches("v\\d+\\.\\d+\\.\\d+(?:-[A-Za-z0-9.-]+)?"))continue;
                String version=tag.substring(1);
                if(compare(version,current)<=0)continue;
                JSONArray assets=r.optJSONArray("assets");
                boolean apk=false;
                if(assets!=null)for(int j=0;j<assets.length();j++)
                    if(assets.getJSONObject(j).optString("name","").endsWith(".apk"))apk=true;
                if(!apk)continue;
                if(best==null||compare(version,best.version)>0)
                    best=new Update(version,r.optString("html_url","https://github.com/crakacr-alt/ASTER-Guard/releases"));
            }
            return best;
        }finally{conn.disconnect();}
    }
    /** Pre-release versions only compare equal on the three numeric segments; never claim automatic replacement. */
    public static int compare(String a,String b){
        String[] aa=a.replaceFirst("^v","").split("[.-]");
        String[] bb=b.replaceFirst("^v","").split("[.-]");
        for(int i=0;i<3;i++){
            int x=part(aa,i),y=part(bb,i);
            if(x!=y)return Integer.compare(x,y);
        }
        return 0;
    }
    private static int part(String[] p,int i){
        if(i>=p.length)return 0;
        try{return Integer.parseInt(p[i]);}catch(NumberFormatException ignored){return 0;}
    }
}
