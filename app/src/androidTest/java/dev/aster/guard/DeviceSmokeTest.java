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
    @Test public void liveCaptureIntentIsExplicitOnly(){
        Intent request=LiveCaptureSession.controlIntent("start","com.example.safeapp");
        assertEquals("start",request.getStringExtra("action"));
        assertEquals("com.example.safeapp",request.getStringExtra("app_filter"));
        assertEquals("127.0.0.1",request.getStringExtra("collector_host"));
        assertFalse(request.getBooleanExtra("tls_decryption",true));
    }
}
