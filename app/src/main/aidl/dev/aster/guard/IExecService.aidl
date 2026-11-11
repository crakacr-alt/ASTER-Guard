package dev.aster.guard;
interface IExecService {
    String inspect(int code);
    String inspectPackage(int code, String packageName);
    String setPrivacyOp(String packageName, String op, boolean deny);
    void destroy();
}
