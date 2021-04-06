package org.demen.androidpowermanager;

import android.app.Activity;
import android.app.Application;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;
import io.flutter.plugin.common.PluginRegistry.Registrar;

/** AndroidPowerManagerPlugin */
public class AndroidPowerManagerPlugin implements MethodChannel.MethodCallHandler, PluginRegistry.ActivityResultListener {

  private static final String METHOD_IS_IGNORING_BATTERY_OPTIMIZATIONS = "isIgnoringBatteryOptimizations";
  private static final String METHOD_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS = "requestIgnoreBatteryOptimizations";
  private static final int REQUEST_CODE_IGNORE_BATTERY_OPTIMIZATIONS = 1224;

  private static final String CHANNEL = "flutter.demen.org/android_power_manager";

  private Activity activity;
  private MethodChannel.Result pendingResult;
  private Handler handler = new Handler(Looper.getMainLooper());

  /**
   * Plugin registration.
   */
  public static void registerWith(Registrar registrar) {
    if (registrar.activity() == null) {
      // If a background flutter view tries to register the plugin, there will be no activity from the registrar,
      // we stop the registering process immediately because the ImagePicker requires an activity.
      return;
    }
    final MethodChannel channel = new MethodChannel(registrar.messenger(), CHANNEL);

    final AndroidPowerManagerPlugin instance = new AndroidPowerManagerPlugin(registrar.activity());
    registrar.addActivityResultListener(instance);
    channel.setMethodCallHandler(instance);
  }

  private AndroidPowerManagerPlugin(Activity activity) {
    this.activity = activity;
  }

  @SuppressWarnings("NullableProblems")
  @Override
  public void onMethodCall(MethodCall call, MethodChannel.Result result) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      switch (call.method) {
        case METHOD_IS_IGNORING_BATTERY_OPTIMIZATIONS:
          PowerManager powerManager = (PowerManager) activity.getSystemService(Application.POWER_SERVICE);
          if (powerManager != null) {
            result.success(powerManager.isIgnoringBatteryOptimizations(activity.getPackageName()));
          } else {
            ClassNotFoundException error = new ClassNotFoundException();
            result.error(error.getMessage(), error.getLocalizedMessage(), error);
          }
          break;
        case METHOD_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS:
          pendingResult = result;
          Intent intent = new Intent();
          intent.setAction(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
          intent.setData(Uri.parse("package:" + activity.getPackageName()));
          activity.startActivityForResult(intent, REQUEST_CODE_IGNORE_BATTERY_OPTIMIZATIONS);
          break;
        default:
          result.notImplemented();
          break;
      }
    } else {
      result.notImplemented();
    }
  }

  @Override
  public boolean onActivityResult(int requestCode, final int resultCode, Intent data) {
    if (requestCode == REQUEST_CODE_IGNORE_BATTERY_OPTIMIZATIONS) {
      if (pendingResult != null) {
        handler.post(new Runnable() {
          @Override
          public void run() {
            pendingResult.success(resultCode == Activity.RESULT_OK);
          }
        });
      }
      return true;
    }
    return false;
  }
}
