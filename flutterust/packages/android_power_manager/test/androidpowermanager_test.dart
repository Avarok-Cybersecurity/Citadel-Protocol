import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:android_power_manager/android_power_manager.dart';

void main() {
  const MethodChannel channel = MethodChannel('androidpowermanager');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await Androidpowermanager.platformVersion, '42');
  });
}
