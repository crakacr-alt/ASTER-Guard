package dev.aster.guard;
interface IExecService {
    String inspect(int code);
    String inspectPackage(int code, String packageName);
    void destroy();
}
