package dev.aster.guard;
import org.junit.Test;
import static org.junit.Assert.*;
public final class PrivacyCodeAnalyzerTest {
    @Test public void tracksAdvertisingId(){
        assertEquals("ad-id",PrivacyCodeAnalyzer.categoryForReference(
            "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;->getAdvertisingIdInfo(Landroid/content/Context;)"));
    }
    @Test public void locatesSensitiveApis(){
        assertEquals("location",PrivacyCodeAnalyzer.categoryForReference(
            "Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)"));
        assertEquals("microphone",PrivacyCodeAnalyzer.categoryForReference(
            "Landroid/media/AudioRecord;->startRecording()V"));
        assertEquals("dynamic-code",PrivacyCodeAnalyzer.categoryForReference(
            "Ldalvik/system/DexClassLoader;-><init>()V"));
    }
    @Test public void neverLabelsUnknownCallAsTracking(){
        assertEquals("",PrivacyCodeAnalyzer.categoryForReference(
            "Ljava/lang/String;->length()I"));
        assertEquals("",PrivacyCodeAnalyzer.categoryForReference(null));
    }
}
