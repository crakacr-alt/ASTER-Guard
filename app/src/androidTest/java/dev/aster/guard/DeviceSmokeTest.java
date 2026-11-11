package dev.aster.guard;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.Assert.*;

/** Runs against an actual Android emulator/device, not JVM mocks. */
@RunWith(AndroidJUnit4.class)
public final class DeviceSmokeTest {
    private Context target(){
        return InstrumentationRegistry.getInstrumentation().getTargetContext();
    }
    @Test public void activityCanLaunch(){
        Intent intent=new Intent(target(),MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Activity activity=InstrumentationRegistry.getInstrumentation().startActivitySync(intent);
        assertNotNull("Main screen must launch",activity);
        InstrumentationRegistry.getInstrumentation().waitForIdleSync();
        assertFalse("Main screen should stay open",activity.isFinishing());
        activity.runOnUiThread(activity::finish);
    }
    @Test public void scannerCanReadPackages(){
        assertTrue("At least ASTER should be discoverable",
            Scanner.scan(target(),new AtomicBoolean(false),(done,total)->{}).size()>0);
    }
    @Test public void deviceHealthAndNetwork(){
        DeviceHealth.Snapshot result=DeviceHealth.snapshot(target());
        assertTrue(result.uptimeMs>=0);
        assertNotNull(NetworkReader.connection(target()));
    }
    @Test public void dexBrowserReadsInstalledApk() throws Exception {
        android.content.pm.ApplicationInfo info=target().getPackageManager()
            .getApplicationInfo(target().getPackageName(),0);
        DexCodeReader reader=DexCodeReader.create();
        DexCodeReader.Index index=reader.index(new String[]{info.sourceDir},target().getPackageName());
        assertTrue("Installed ASTER must contain DEX classes",index.dexFiles>0);
        assertFalse(index.classes.isEmpty());
        boolean found=false;
        for(DexCodeReader.Item item:index.classes){
            if(item.type.equals("Ldev/aster/guard/MainActivity;")){
                found=true;
                java.util.List<org.jf.dexlib2.iface.Method> methods=reader.methods(item);
                assertFalse(methods.isEmpty());
                for(org.jf.dexlib2.iface.Method m:methods){
                    if(m.getImplementation()!=null){
                        String opcodes=reader.disassemble(item,m);
                        assertTrue(opcodes.contains(".method"));
                        assertTrue(opcodes.contains(".registers"));
                        break;
                    }
                }
                break;
            }
        }
        assertTrue("APK browser should locate ASTER MainActivity",found);
    }
    @Test public void fileInspectorSafStyleStreamWorks() throws Exception {
        byte[] pdf="%PDF-1.4\\n/JavaScript /OpenAction".getBytes("US-ASCII");
        FileInspector.Report result=FileInspector.analyze(
            new java.io.ByteArrayInputStream(pdf),null,"sample.pdf","application/pdf",
            pdf.length,()->false,n->{});
        assertEquals("PDF",result.format);
        assertEquals(64,result.sha256.length());
        assertFalse(result.findings.isEmpty());
    }
    @Test public void liveCaptureIntentIsExplicitOnly(){
        Intent request=LiveCaptureSession.controlIntent("start","com.example.safeapp");
        assertEquals("start",request.getStringExtra("action"));
        assertEquals("com.example.safeapp",request.getStringExtra("app_filter"));
        assertEquals("127.0.0.1",request.getStringExtra("collector_host"));
        assertFalse(request.getBooleanExtra("tls_decryption",true));
    }
}
