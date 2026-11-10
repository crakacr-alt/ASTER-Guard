package dev.aster.guard;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** Opt-in, exact-version Maven package queries to OSV.dev. No guessing by SDK family. */
public final class OsvAdvisor {
    public static final class Finding {
        public final String packageId, ids;
        public Finding(String p,String ids){packageId=p;this.ids=ids;}
    }
    private OsvAdvisor(){}
    public static List<Finding> query(List<ApkAuditor.MavenPackage> packages)throws Exception {
        List<Finding> out=new ArrayList<>();
        if(packages.isEmpty())return out;
        JSONArray queries=new JSONArray();
        int count=Math.min(10,packages.size());
        for(int i=0;i<count;i++){
            ApkAuditor.MavenPackage p=packages.get(i);
            JSONObject v=new JSONObject();
            v.put("package",new JSONObject().put("ecosystem","Maven").put("name",p.group+":"+p.name));
            v.put("version",p.version);
            queries.put(v);
        }
        byte[] payload=new JSONObject().put("queries",queries).toString().getBytes(StandardCharsets.UTF_8);
        HttpURLConnection conn=(HttpURLConnection)new URL("https://api.osv.dev/v1/querybatch").openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(7000);conn.setReadTimeout(7000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type","application/json");
        conn.setRequestProperty("Accept","application/json");
        conn.getOutputStream().write(payload);
        try{
            if(conn.getResponseCode()!=200)throw new IllegalStateException("OSV HTTP "+conn.getResponseCode());
            ByteArrayOutputStream mem=new ByteArrayOutputStream();
            byte[] bytes=new byte[8192];int total=0,n;
            try(InputStream in=conn.getInputStream()){
                while((n=in.read(bytes))!=-1){
                    total+=n;if(total>512*1024)throw new IllegalStateException("Слишком большой ответ OSV");
                    mem.write(bytes,0,n);
                }
            }
            JSONArray results=new JSONObject(mem.toString("UTF-8")).getJSONArray("results");
            for(int i=0;i<Math.min(count,results.length());i++){
                JSONArray vulns=results.getJSONObject(i).optJSONArray("vulns");
                if(vulns==null||vulns.length()==0)continue;
                StringBuilder ids=new StringBuilder();
                for(int j=0;j<Math.min(8,vulns.length());j++){
                    if(j>0)ids.append(", ");
                    ids.append(vulns.getJSONObject(j).optString("id","неизвестный ID"));
                }
                out.add(new Finding(packages.get(i).toString(),ids.toString()));
            }
            return out;
        }finally{conn.disconnect();}
    }
}
