package dev.aster.guard;
import org.junit.Test;
import static org.junit.Assert.*;
public class UpdateCheckerTest {
    @Test public void compareVersionNumbers(){
        assertTrue(UpdateChecker.compare("0.3.0","0.2.0")>0);
        assertTrue(UpdateChecker.compare("0.9.0","0.10.0")<0);
        assertEquals(0,UpdateChecker.compare("0.3.0-test","0.3.0"));
    }
}
