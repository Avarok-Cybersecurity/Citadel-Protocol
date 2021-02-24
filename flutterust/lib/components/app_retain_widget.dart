import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutterust/main.dart';

class AppRetainWidget extends StatelessWidget {
  AppRetainWidget({Key key, this.child}) : super(key: key);

  final Widget child;

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: () async {
        if (Platform.isAndroid) {
          if (Navigator.of(context).canPop()) {
            return true;
          } else {
            print("Sending program to background safely ...");
            RustSubsystem.bridge.sendToBackground();
            return false;
          }
        } else {
          return true;
        }
      },
      child: child,
    );
  }
}