package dev.aster.guard;
import org.junit.Test;
import static org.junit.Assert.*;
public class RiskEngineTest {
    @Test public void benignHasNoScore() {
        assertEquals(0,RiskEngine.assess(new RiskEngine.Signals()).score);
    }
    @Test public void combinedCapabilitiesIncreaseRisk() {
        RiskEngine.Signals s=new RiskEngine.Signals();
        s.overlay=true; s.accessibilityService=true; s.canInstallPackages=true;
        assertTrue(RiskEngine.assess(s).score>=60);
        assertTrue(RiskEngine.assess(s).reasons.size()>=3);
    }
    @Test public void systemAppsAreExcludedFromHeuristics() {
        RiskEngine.Signals s=new RiskEngine.Signals(); s.system=true; s.debuggable=true;
        assertEquals(0,RiskEngine.assess(s).score);
    }
    @Test public void scoreNeverExceedsHundred() {
        RiskEngine.Signals s=new RiskEngine.Signals();
        s.signerChanged=true; s.overlay=true; s.accessibilityService=true;
        s.canInstallPackages=true; s.deviceAdmin=true; s.debuggable=true;
        assertEquals(100,RiskEngine.assess(s).score);
    }
}
