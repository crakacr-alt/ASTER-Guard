package dev.aster.guard;

import org.junit.Test;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.Assert.*;

public final class FileInspectorTest {
    private static FileInspector.Report run(byte[] data,String name)throws Exception{
        return FileInspector.analyze(new ByteArrayInputStream(data),
            new ByteArrayInputStream(data),name,"application/octet-stream",data.length,
            ()->false,n->{});
    }
    private static boolean has(FileInspector.Report r,String key){
        for(FileInspector.Finding x:r.findings)if(x.title.contains(key))return true;
        return false;
    }
    private static byte[] zip(String name,byte[] bytes)throws Exception{
        ByteArrayOutputStream output=new ByteArrayOutputStream();
        try(ZipOutputStream zip=new ZipOutputStream(output)){
            ZipEntry entry=new ZipEntry(name);
            zip.putNextEntry(entry);
            zip.write(bytes);
            zip.closeEntry();
        }
        return output.toByteArray();
    }
    @Test public void pdfJavascriptAndOpenAction() throws Exception {
        byte[] pdf="%PDF-1.7\n1 0 obj <</JavaScript 2 0 R /OpenAction 3 0 R>>".getBytes(StandardCharsets.ISO_8859_1);
        FileInspector.Report r=run(pdf,"receipt.pdf");
        assertEquals("PDF",r.format);
        assertTrue(has(r,"JavaScript"));
        assertTrue(has(r,"открытии"));
        assertEquals(64,r.sha256.length());
        assertTrue(r.complete);
    }
    @Test public void benignMinimalPngIsNotFlaggedAsExecutable() throws Exception {
        byte[] png={(byte)0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0,0};
        FileInspector.Report r=run(png,"image.png");
        assertEquals("PNG",r.format);
        assertFalse(r.executable);
        assertFalse(has(r,"Расширение"));
        assertFalse(has(r,"Исполняемый"));
    }
    @Test public void renamedExecutableIsFlagged() throws Exception {
        byte[] pe={0x4d,0x5a,0,0,0,0,0,0};
        FileInspector.Report r=run(pe,"portrait.png");
        assertTrue(r.executable);
        assertTrue(has(r,"Расширение"));
        assertTrue(has(r,"Исполняемый"));
    }
    @Test public void officeMacroFileDetected() throws Exception {
        FileInspector.Report r=run(zip("word/vbaProject.bin",new byte[]{1,2,3}),"proposal.docm");
        assertEquals(1,r.macroFiles);
        assertTrue(has(r,"VBA"));
        assertTrue(r.archive);
        assertFalse(r.zipPartial);
    }
    @Test public void apkInventoryAndDexPresent() throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(ZipOutputStream zip=new ZipOutputStream(out)){
            zip.putNextEntry(new ZipEntry("AndroidManifest.xml"));zip.write(new byte[]{1,2});zip.closeEntry();
            zip.putNextEntry(new ZipEntry("classes.dex"));zip.write(new byte[]{3,4});zip.closeEntry();
            zip.putNextEntry(new ZipEntry("lib/arm64-v8a/libexample.so"));zip.write(new byte[]{5});zip.closeEntry();
        }
        FileInspector.Report r=run(out.toByteArray(),"not_installed.apk");
        assertTrue(r.apk);assertEquals(1,r.classesDex);
        assertEquals(1,r.nativeLibraries);
        assertEquals(3,r.entries);
    }
    @Test public void archiveTraversalDetectedWithoutExtracting() throws Exception {
        FileInspector.Report r=run(zip("../escape.txt",new byte[]{42}),"unsafe.zip");
        assertTrue(has(r,"путь вне архива"));
    }
    @Test public void fileDataRemainsPrivateAndNoExecution() throws Exception {
        FileInspector.Report r=run("hello world".getBytes(StandardCharsets.UTF_8),"note.txt");
        assertTrue(r.complete);
        assertEquals(64,r.sha256.length());
        assertFalse(r.executable);
        assertEquals(0,r.embeddedExecutables);
    }
    @Test public void cancellationInterruptsReading()throws Exception{
        try {
            FileInspector.analyze(new ByteArrayInputStream(new byte[]{1,2}),null,
                "tiny.bin","",2,()->true,null);
            fail("Expected cancellation");
        }catch(java.io.IOException expected){assertTrue(expected.getMessage().contains("отменена"));}
    }
}
