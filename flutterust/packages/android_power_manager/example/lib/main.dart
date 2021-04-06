import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:android_power_manager/android_power_manager.dart';

void main() => runApp(MyApp());

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _isIgnoringBatteryOptimizations = 'Unknown';

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

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

  Future<String> _checkBatteryOptimizations() async {
    String isIgnoringBatteryOptimizations;
    // Platform messages may fail, so we use a try/catch PlatformException.
    try {
      isIgnoringBatteryOptimizations =
      '${await AndroidPowerManager.isIgnoringBatteryOptimizations}';
    } on PlatformException {
      isIgnoringBatteryOptimizations = 'Failed to get platform version.';
    }
    return isIgnoringBatteryOptimizations;
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Text('Running on: $_isIgnoringBatteryOptimizations\n'),
        ),
        floatingActionButton: FloatingActionButton(
          onPressed: () async {
            bool success =
            await AndroidPowerManager.requestIgnoreBatteryOptimizations();
            if (success) {
              String isIgnoringBatteryOptimizations =
              await _checkBatteryOptimizations();
              setState(() {
                _isIgnoringBatteryOptimizations =
                    isIgnoringBatteryOptimizations;
              });
            }
          },
          child: Icon(Icons.power),
        ),
      ),
    );
  }
}
