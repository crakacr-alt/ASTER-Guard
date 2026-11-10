package dev.aster.guard;

import android.app.Activity;
import android.content.Intent;
import android.test.InstrumentationTestCase;
import java.util.concurrent.atomic.AtomicBoolean;

/** Run on an actual emulator/device, not a host-side mocked Android runtime. */
public final class DeviceSmokeTest extends InstrumentationTestCase {
    public void testActivityCanLaunch() {
        Intent i=new Intent(getInstrumentation().getTargetContext(),MainActivity.class);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Activity activity=getInstrumentation().startActivitySync(i);
        assertNotNull(activity);
        getInstrumentation().waitForIdleSync();
        assertFalse(activity.isFinishing());
        activity.finish();
    }
    public void testScannerCanReadPackages() {
        assertTrue(Scanner.scan(getInstrumentation().getTargetContext(),
            new AtomicBoolean(false),(completed,total)->{}).size()>0);
    }
    public void testDeviceHealthAndNetwork() {
        DeviceHealth.Snapshot s=DeviceHealth.snapshot(getInstrumentation().getTargetContext());
        assertTrue(s.uptimeMs>=0);
        assertNotNull(NetworkReader.connection(getInstrumentation().getTargetContext()));
    }
}
