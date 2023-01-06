# Android Power Manager plugin for Flutter

A Flutter plugin for Android for invoking Power Manager api.

*Note*: This plugin is still under development, and some APIs might not be available yet. [Feedback welcome](https://github.com/de-men/flutter_android/issues) and [Pull Requests](https://github.com/de-men/flutter_android/pulls) are most welcome!

## Installation

First, add `android_power_manager` as a [dependency in your pubspec.yaml file](https://flutter.io/platform-plugins/).

### Android

If you want to request ignoring battery optimizations please specify your permission in the application manifest `android/app/src/main/AndroidManifest.xml`:

```xml
<manifest...>
  <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"/>
</manifest...>
```

### Example

```dart
import 'package:android_power_manager/android_power_manager.dart';

// Platform messages are asynchronous, so we initialize in an async method.
Future<void> initPlatformState() async {
  // If the widget was removed from the tree while the asynchronous platform
  // message was in flight, we want to discard the reply rather than calling
  // setState to update our non-existent appearance.
  if (!mounted) return;
  String isIgnoringBatteryOptimizations = await _checkBatteryOptimizations();
  setState(() {
    _isIgnoringBatteryOptimizations = isIgnoringBatteryOptimizations;
  });
}
```