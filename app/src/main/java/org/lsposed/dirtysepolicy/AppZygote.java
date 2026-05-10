package org.lsposed.dirtysepolicy;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.SELinux;
import android.system.Os;

public final class AppZygote implements ZygotePreload {
    static String result = "ERROR: app zygote not called";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        var uid = Os.getuid();
        if (uid != appInfo.uid) {
            result = "FAILED: UID mismatch: " + uid + " != app uid " + appInfo.uid;
            return;
        }
        if (!SELinux.isSELinuxEnabled()) {
            result = "FAILED: SELinux is disabled";
            return;
        }
        if (!SELinux.isSELinuxEnforced()) {
            result = "FAILED: SELinux is permissive";
            return;
        }
        var context = SELinux.getContext();
        if (!context.startsWith("u:r:app_zygote:s0")) {
            result = "FAILED: unexpected SELinux context: " + context;
            return;
        }
        var pidContext = SELinux.getPidContext(Os.getpid());
        if (!pidContext.equals(context)) {
            result = "FAILED: PID context mismatch: " + pidContext;
            return;
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!procContext.equals(context)) {
            result = "FAILED: /proc/self context mismatch: " + procContext;
            return;
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:isolated_app:s0", "process", "dyntransition")) {
            result = "FAILED: cannot check SELinux access";
            return;
        }
        var sb = new StringBuilder();
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:r:magisk:s0", "binder", "call")) {
            sb.append("found Magisk; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:r:ksu:s0", "binder", "call")) {
            sb.append("found KernelSU; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read")) {
            sb.append("found LSPosed; ");
        }
        if (sb.length() == 0) {
            result = "OK: no dirty sepolicy found";
        } else {
            result = "WARNING: " + sb;
        }
    }
}
