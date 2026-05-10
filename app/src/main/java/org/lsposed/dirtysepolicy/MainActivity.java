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
    private TextView textView;
    private final ServiceConnection connection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder binder) {
            var server = IDirtySepolicyService.Stub.asInterface(binder);
            try {
                textView.setText(server.getResult());
            } catch (RemoteException e) {
                textView.setText(Log.getStackTraceString(e));
            }
            unbindService(this);
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
        }

        @Override
        public void onNullBinding(ComponentName name) {
            textView.setText("ERROR: Fake Environment");
            unbindService(this);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        var layout = new RelativeLayout(this);
        textView = new TextView(this);
        textView.setTextIsSelectable(true);
        textView.setTextSize(20);
        var def = "INFO: Wiaiting for service...";
        textView.setText(def);
        var params = new RelativeLayout.LayoutParams(
                RelativeLayout.LayoutParams.WRAP_CONTENT,
                RelativeLayout.LayoutParams.WRAP_CONTENT);
        params.addRule(RelativeLayout.CENTER_HORIZONTAL);
        params.addRule(RelativeLayout.CENTER_VERTICAL);
        layout.addView(textView, params);
        setContentView(layout);
        try {
            if (bindIsolatedService(new Intent(this, DirtySepolicyService.class),
                    Context.BIND_AUTO_CREATE, "dirtysepolicy", getMainExecutor(), connection)) {
                textView.postDelayed(() -> {
                    if (textView.getText().toString().equals(def)) {
                        textView.setText("WARNING: Service connection timedout, app zygote crashed?");
                        unbindService(connection);
                    }
                }, 5000);
            } else {
                textView.setText("ERROR: Failed to bind service, service disabled?");
                unbindService(connection);
            }
        } catch (SecurityException e) {
            textView.setText(Log.getStackTraceString(e));
            unbindService(connection);
        }
    }

}
