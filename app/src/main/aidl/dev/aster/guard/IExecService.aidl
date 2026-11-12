package dev.aster.guard;
import android.os.ParcelFileDescriptor;
interface IExecService {
    String inspect(int code);
    String inspectPackage(int code, String packageName);
    String setPrivacyOp(String packageName, String op, boolean deny);
    String installApk(in ParcelFileDescriptor content, long bytes, boolean bypassLowTarget, boolean testOnly);
    void destroy();
}
