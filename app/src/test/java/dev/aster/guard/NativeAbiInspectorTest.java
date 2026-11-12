package dev.aster.guard;
import org.junit.Test;
import java.util.Arrays;
import static org.junit.Assert.*;
public class NativeAbiInspectorTest {
    private byte[] elf(int bits,int machine) {
        byte[] d=new byte[64];
        d[0]=0x7f;d[1]='E';d[2]='L';d[3]='F';
        d[4]=(byte)(bits==32?1:2);d[5]=1;
        d[18]=(byte)machine;d[19]=(byte)(machine>>>8);
        return d;
    }
    @Test public void recognizesRealMachineArchitectures() {
        assertEquals("armeabi-v7a",NativeAbiInspector.header(elf(32,40),64).abi);
        assertEquals("arm64-v8a",NativeAbiInspector.header(elf(64,183),64).abi);
        assertEquals("x86",NativeAbiInspector.header(elf(32,3),64).abi);
        assertEquals("x86_64",NativeAbiInspector.header(elf(64,62),64).abi);
    }
    @Test public void movingHeadersDoesNotConvertMachineCode() {
        NativeAbiInspector.Elf arm32=NativeAbiInspector.header(elf(32,40),64);
        assertTrue(arm32.valid);
        assertFalse(NativeAbiInspector.supported(arm32,new String[]{"arm64-v8a"}));
        assertTrue(NativeAbiInspector.supported(arm32,new String[]{"arm64-v8a","armeabi-v7a"}));
    }
    @Test public void wrongOrMissingElfIsRejected() {
        assertFalse(NativeAbiInspector.header(new byte[]{0,1,2},3).valid);
        assertFalse(NativeAbiInspector.header(elf(64,40),64).valid);
    }
}
