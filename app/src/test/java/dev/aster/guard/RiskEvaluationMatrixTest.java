package dev.aster.guard;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Fully SYNTHETIC feature-vector matrix. It exercises deterministic rules,
 * not real malware detection effectiveness. No live malware/APK corpus.
 */
public final class RiskEvaluationMatrixTest {
    private static RiskEngine.Signals row(int bits){
        RiskEngine.Signals s=new RiskEngine.Signals();
        s.overlay=(bits&1)!=0;
        s.accessibilityService=(bits&2)!=0;
        s.canInstallPackages=(bits&4)!=0;
        s.debuggable=(bits&8)!=0;
        s.readsSms=(bits&16)!=0;
        s.receivesSms=(bits&32)!=0;
        s.internet=(bits&64)!=0;
        s.readsCallLog=(bits&128)!=0;
        s.signerChanged=(bits&256)!=0;
        s.deviceAdmin=(bits&512)!=0;
        return s;
    }
    @Test public void fixedSyntheticRegressionMatrix(){
        // Benign patterns: capabilities can be legitimate.
        int[] expectedNotFlagged={
            0,1,2,4,8,16|32|64,512,128|64
        };
        // Suspicious FEATURE COMBINATIONS; cannot imply infected APKs.
        int[] expectedFlagged={
            1|2,2|4,1|2|4,256,1|4|128|64,8|2|4
        };
        int falsePos=0,truePos=0;
        for(int features:expectedNotFlagged)
            if(RiskEngine.assess(row(features)).score>=35)falsePos++;
        for(int features:expectedFlagged)
            if(RiskEngine.assess(row(features)).score>=35)truePos++;
        System.out.println("SYNTHETIC matrix only: flagged="+truePos+"/"+expectedFlagged.length+
            ", false_flags="+falsePos+"/"+expectedNotFlagged.length);
        assertEquals("Synthetic unexpected flagged benign pattern",0,falsePos);
        assertEquals("Synthetic suspicious patterns all recognized",expectedFlagged.length,truePos);
    }
    @Test public void scoreAlwaysBoundedOnFeatureCombinations(){
        for(int bits=0;bits<1024;bits++){
            int score=RiskEngine.assess(row(bits)).score;
            assertTrue(score>=0&&score<=100);
        }
    }
}
