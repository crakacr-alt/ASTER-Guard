package dev.aster.guard;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;

public final class PcapInspectorTest {
    @Test public void malformedCaptureFails() {
        try{PcapInspector.parseBytes(new byte[8]);fail("Must reject truncated PCAP");}
        catch(IOException expected){}
    }
    @Test public void emptyPcapAccepted()throws Exception {
        byte[] a=new byte[24];
        a[0]=(byte)0xd4;a[1]=(byte)0xc3;a[2]=(byte)0xb2;a[3]=(byte)0xa1;
        a[20]=1; // Ethernet DLT
        assertEquals(0,PcapInspector.parseBytes(a).packets);
    }
}
