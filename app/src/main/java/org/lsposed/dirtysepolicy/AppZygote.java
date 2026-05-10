package org.lsposed.dirtysepolicy;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.SELinux;
import android.system.Os;

public final class AppZygote implements ZygotePreload {
    static String result = "ERROR: app zygote not called";

    @Override
    public void doPreload(ApplicationInfo appInfo) {
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
        if (!context.startsWith("u:r:app_zygote:s0")) {
            result = "ERROR: unexpected SELinux context: " + context;
            return;
        }
        var pidContext = SELinux.getPidContext(Os.getpid());
        if (!pidContext.equals(context)) {
            result = "ERROR: PID context mismatch: " + pidContext;
            return;
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!procContext.equals(context)) {
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
        var sb = new StringBuilder();
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
    }
}
