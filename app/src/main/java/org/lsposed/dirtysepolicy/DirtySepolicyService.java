package org.lsposed.dirtysepolicy;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;

public class DirtySepolicyService extends Service {
    private final IDirtySepolicyService.Stub binder = new IDirtySepolicyService.Stub() {
        @Override
        public String getResult() {
            return AppZygote.result;
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        if (Process.isIsolated()) {
            return binder;
        } else {
            return null;
        }
    }
}
