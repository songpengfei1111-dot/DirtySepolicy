package android.os;

public class SELinux {
    public static native boolean isSELinuxEnabled();

    public static native boolean isSELinuxEnforced();

    public static native String getFileContext(String path);

    public static native String getContext();

    public static native String getPidContext(int pid);

    public static native boolean checkSELinuxAccess(String scon, String tcon, String tclass, String perm);
}
