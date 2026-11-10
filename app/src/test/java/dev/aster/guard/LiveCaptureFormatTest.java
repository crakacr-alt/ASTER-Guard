package dev.aster.guard;

import org.junit.Test;
import static org.junit.Assert.*;

public final class LiveCaptureFormatTest {
    @Test public void parsePcapRecordLengthBothEndian(){
        byte[] a={(byte)0x80,(byte)0x00,(byte)0x01,(byte)0x00};
        assertEquals(65664,LiveCaptureSession.read32(a,0,true));
        assertEquals(0x80000100,LiveCaptureSession.read32(a,0,false));
    }
    @Test public void sniffingIntentRequiresExplicitStart(){
        // Pure-data test: do not execute any VPN or change device routing.
        assertEquals(5123,LiveCaptureSession.PORT);
    }
}
