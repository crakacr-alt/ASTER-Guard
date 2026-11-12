package dev.aster.guard;
import org.junit.Test;
import static org.junit.Assert.*;
public class InstallAdvisorTest {
    @Test public void minSdkCannotBeBypassed() {
        InstallAdvisor.Advice x=InstallAdvisor.preflight(30,35,28);
        assertEquals("INSTALL_FAILED_OLDER_SDK",x.code);
        assertFalse(x.legacyTargetBypass);
    }
    @Test public void lowTargetSdkCanBeFlaggedForConsentDrivenBypass() {
        assertTrue(InstallAdvisor.preflight(35,21,22).legacyTargetBypass);
        assertFalse(InstallAdvisor.preflight(33,21,22).legacyTargetBypass);
    }
    @Test public void signatureAbiAndSplitsHaveSpecificExplanations() {
        assertEquals("SIGNATURE_MISMATCH",InstallAdvisor.failure("Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE]").code);
        assertEquals("ABI_MISMATCH",InstallAdvisor.failure("INSTALL_FAILED_NO_MATCHING_ABIS").code);
        assertEquals("MISSING_SPLITS",InstallAdvisor.failure("INSTALL_FAILED_MISSING_SPLIT").code);
    }
}
