import 'dart:async';

import 'package:flutter/services.dart';

class AndroidPowerManager {
  static const MethodChannel _channel =
  const MethodChannel('flutter.demen.org/android_power_manager');

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  static Future<bool?> get isIgnoringBatteryOptimizations async =>
      await _channel.invokeMethod<bool>('isIgnoringBatteryOptimizations');

  static Future<bool?> requestIgnoreBatteryOptimizations() async =>
      await _channel.invokeMethod<bool>('requestIgnoreBatteryOptimizations');
}
