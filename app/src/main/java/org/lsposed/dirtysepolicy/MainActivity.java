package org.lsposed.dirtysepolicy;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;
import android.widget.RelativeLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "dirtysepolicy";
    private TextView textView;
    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            var server = IDirtySepolicyService.Stub.asInterface(binder);
            try {
                textView.setText(server.getResult());
                unbindService(this);
            } catch (RemoteException e) {
                textView.setText(Log.getStackTraceString(e));
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
        }

        @Override
        public void onNullBinding(ComponentName name) {
            textView.setText("ERROR: Fake Environment");
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        var layout = new RelativeLayout(this);
        textView = new TextView(this);
        textView.setTextIsSelectable(true);
        textView.setTextSize(20);
        textView.setText(bind() ? "WARNING: Service not connected" : "ERROR: Failed to bind service");
        var params = new RelativeLayout.LayoutParams(
                RelativeLayout.LayoutParams.WRAP_CONTENT,
                RelativeLayout.LayoutParams.WRAP_CONTENT);
        params.addRule(RelativeLayout.CENTER_HORIZONTAL);
        params.addRule(RelativeLayout.CENTER_VERTICAL);
        layout.addView(textView, params);
        setContentView(layout);
    }

    private boolean bind() {
        try {
            return bindIsolatedService(new Intent(this, DirtySepolicyService.class),
                    Context.BIND_AUTO_CREATE, TAG, getMainExecutor(), connection);
        } catch (Exception e) {
            Log.e(TAG, "Can not bind service", e);
            return false;
        }
    }

}
