package org.lsposed.dirtysepolicy;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.SELinux;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class AppZygote implements ZygotePreload {
    private static final String KSU_CONTEXT = "u:r:ksu:s0";
    private static final String KSU_FILE_CONTEXT = "u:r:ksu_file:s0";
    private static final String MAGISK_CONTEXT = "u:r:magisk:s0";
    private static final String MAGISK_FILE_CONTEXT = "u:r:magisk_file:s0";
    private static final String LSPOSED_FILE_CONTEXT = "u:r:lsposed_file:s0";
    private static final String XPOSED_DATA_CONTEXT = "u:r:xposed_data:s0";

    static String result = "ERROR: app zygote not called";
    static volatile boolean debug = false;
    static volatile ProcAttrCurrentResult ksuProcAttrCurrentResult = ProcAttrCurrentResult.notRun(KSU_CONTEXT);
    static volatile ProcAttrCurrentResult ksuFileProcAttrCurrentResult = ProcAttrCurrentResult.notRun(KSU_FILE_CONTEXT);
    static volatile ProcAttrCurrentResult magiskProcAttrCurrentResult = ProcAttrCurrentResult.notRun(MAGISK_CONTEXT);
    static volatile ProcAttrCurrentResult magiskFileProcAttrCurrentResult = ProcAttrCurrentResult.notRun(MAGISK_FILE_CONTEXT);
    static volatile ProcAttrCurrentResult lsposedFileProcAttrCurrentResult = ProcAttrCurrentResult.notRun(LSPOSED_FILE_CONTEXT);
    static volatile ProcAttrCurrentResult xposedDataProcAttrCurrentResult = ProcAttrCurrentResult.notRun(XPOSED_DATA_CONTEXT);

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        debug = (appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        var uid = Os.getuid();
        if (uid != appInfo.uid) {
            result = "ERROR: UID mismatch: " + uid + " != app uid " + appInfo.uid;
            return;
        }
        if (!SELinux.isSELinuxEnabled()) {
            result = "ERROR: SELinux is disabled";
            return;
        }
        var context = SELinux.getContext();
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            result = "ERROR: unexpected SELinux context: " + context;
            return;
        }
        var pidContext = SELinux.getPidContext(Os.getpid());
        if (!context.equals(pidContext)) {
            result = "ERROR: PID context mismatch: " + pidContext;
            return;
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!context.equals(procContext)) {
            result = "ERROR: /proc/self context mismatch: " + procContext;
            return;
        }
        if (!SELinux.isSELinuxEnforced()) {
            result = "ERROR: SELinux is permissive";
            return;
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:isolated_app:s0", "process", "dyntransition")) {
            result = "ERROR: cannot check SELinux access";
            return;
        }
        ksuProcAttrCurrentResult = runProcAttrCurrentProbe(KSU_CONTEXT);
        ksuFileProcAttrCurrentResult = runProcAttrCurrentProbe(KSU_FILE_CONTEXT);
        magiskProcAttrCurrentResult = runProcAttrCurrentProbe(MAGISK_CONTEXT);
        magiskFileProcAttrCurrentResult = runProcAttrCurrentProbe(MAGISK_FILE_CONTEXT);
        lsposedFileProcAttrCurrentResult = runProcAttrCurrentProbe(LSPOSED_FILE_CONTEXT);
        xposedDataProcAttrCurrentResult = runProcAttrCurrentProbe(XPOSED_DATA_CONTEXT);
        var sb = new StringBuilder();
        if (ksuProcAttrCurrentResult.detected() || ksuFileProcAttrCurrentResult.detected()) {
            sb.append("found KernelSU; ");
        }
        if (magiskProcAttrCurrentResult.detected() || magiskFileProcAttrCurrentResult.detected()) {
            sb.append("found Magisk; ");
        }
        if (lsposedFileProcAttrCurrentResult.detected()) {
            sb.append("found LSPosed; ");
        }
        if (xposedDataProcAttrCurrentResult.detected()) {
            sb.append("found Xposed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:fsck_untrusted:s0", "u:r:fsck_untrusted:s0", "capability", "sys_admin")) {
            sb.append("neverallow violated; ");
        }
        if (Build.TYPE.equals("user") && SELinux.checkSELinuxAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            sb.append("found AOSP su in user build; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:adbd:s0", "u:r:adbroot:s0", "binder", "call")) {
            sb.append("found adb_root; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:r:magisk:s0", "binder", "call")) {
            sb.append("found Magisk; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file", "read")) {
            sb.append("found KernelSU; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read")) {
            sb.append("found LSPosed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:xposed_data:s0", "file", "read")) {
            sb.append("found Xposed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            sb.append("found ZygiskNext; ");
        }
        if (sb.length() == 0) {
            result = "OK: no dirty sepolicy found";
        } else {
            result = "WARNING: " + sb;
        }
        if (debug) {
            result = "\n\n\n\n\n\n" + ksuProcAttrCurrentResult.formatMultiline("A ksu") + "\n\n"
                    + ksuFileProcAttrCurrentResult.formatMultiline("A ksu_file") + "\n\n"
                    + magiskProcAttrCurrentResult.formatMultiline("A magisk") + "\n\n"
                    + magiskFileProcAttrCurrentResult.formatMultiline("A magisk_file") + "\n\n"
                    + lsposedFileProcAttrCurrentResult.formatMultiline("A lsposed_file") + "\n\n"
                    + xposedDataProcAttrCurrentResult.formatMultiline("A xposed_data") + "\n\n"
                    + result + "\n\n\n\n";
        }
    }

    private static ProcAttrCurrentResult runProcAttrCurrentProbe(String targetContext) {
        try (var out = new FileOutputStream("/proc/self/attr/current")) {
            Os.write(out.getFD(), targetContext.getBytes(StandardCharsets.UTF_8), 0, targetContext.getBytes(StandardCharsets.UTF_8).length);
            return ProcAttrCurrentResult.success(targetContext, "write succeeded");
        } catch (SecurityException e) {
            return ProcAttrCurrentResult.security(targetContext, e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (IOException e) {
            return classifyIOException(targetContext, e);
        } catch (ErrnoException e) {
            return classifyErrnoException(targetContext, e);
        }
    }

    private static ProcAttrCurrentResult classifyIOException(String targetContext, IOException e) {
        var message = e.getMessage();
        var detail = e.getClass().getSimpleName() + ": " + message;
        if (message != null && message.toLowerCase().contains("invalid argument")) {
            return ProcAttrCurrentResult.einval(targetContext, detail);
        }
        return ProcAttrCurrentResult.nonEinval(targetContext, detail);
    }

    private static ProcAttrCurrentResult classifyErrnoException(String targetContext, ErrnoException e) {
        var detail = e.getClass().getSimpleName() + ": errno=" + e.errno + ", " + e.getMessage();
        if (e.errno == OsConstants.EINVAL) {
            return ProcAttrCurrentResult.einval(targetContext, detail);
        }
        return ProcAttrCurrentResult.nonEinval(targetContext, detail);
    }
}


