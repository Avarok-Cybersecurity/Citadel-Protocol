import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/login.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/themes/default.dart';

import '../utils.dart';

class LoginScreen extends StatefulWidget {
  static const int IDX = 0;

  LoginScreen({Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() => _LoginScreen();
  
}

class _LoginScreen extends State<LoginScreen> {
  final usernameController = TextEditingController();
  final passwordController = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  static const List<String> levels = ["High", "Very High", "Extreme", "Ultra", "Maximum"];
  String securityLevel = levels.first;

  SendPort port;

  _LoginScreen() {
    ReceivePort port = ReceivePort("Login Screen Recv Port");
    this.port = port.sendPort;

    port.listen((message) async {
      print("RECV signal to update state");
      await handleUISignal(message);

      setState(() {});
    });
  }

  Future<void> handleUISignal(LoginUISignal signal) async {
    switch (signal.signal) {
      case LoginUpdateSignalType.LoginFailure:
      //Utils.popup(context, "Registration failed", signal.message);
        await EasyLoading.dismiss();
        await EasyLoading.showError(signal.message, dismissOnTap: true);
        //await EasyLoading.dismiss();
        break;

      case LoginUpdateSignalType.LoginSuccess:
        await EasyLoading.dismiss();
        await EasyLoading.showSuccess(signal.message, dismissOnTap: true);
        //await EasyLoading.dismiss();
        break;

      default: return;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Form(
      key: _formKey,
      child: SingleChildScrollView(
        child: Padding(
          padding: EdgeInsets.symmetric(vertical: 100, horizontal: 50),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: <Widget>[
              DefaultTextFormField(true, "Username", controller: this.usernameController),
              DefaultTextFormField(false, "Password", isPassword: true, controller: this.passwordController),
              DropdownButtonFormField(
                value: securityLevel,

                onChanged: (String newValue) {
                  setState(() {
                    this.securityLevel = newValue;
                  });
                },

                items: levels
                    .map<DropdownMenuItem<String>>((String value) {
                  return DropdownMenuItem<String>(
                    value: value,
                    child: Text(value),
                  );
                }).toList(),

                decoration: InputDecoration(
                    labelText: "Security Level"
                ),
              ),
              Padding(
                padding: EdgeInsets.symmetric(vertical: 10),
                child: ElevatedButton(
                    child: Text("Connect"),
                    onPressed: () { performLogin(this.port); }
                ),
              )
            ],
          ),
        )
      )
    );
  }

  void performLogin(SendPort port) async {
    FocusManager.instance.primaryFocus.unfocus();
    await EasyLoading.show();
    print("Username: " + this.usernameController.text);
    print("Password: " + this.passwordController.text);
    print("Security setting: " + this.securityLevel);
    this._formKey.currentState.save();
    var cmd = "connect " +
        this.usernameController.text +
        " -s " + levels.indexOf(this.securityLevel).toString() +
        " --password " + this.passwordController.text +
        " --ffi" +
        " --fcm-api-key " + Utils.apiKey +
        " --fcm-token " + Utils.nodeClientToken;

    print("Executing: " + cmd);
    (await RustSubsystem.bridge.executeCommand(cmd))
    .ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp, handler: LoginHandler(port, this.usernameController.text)));
  }

  @override
  void dispose() {
    this.usernameController.dispose();
    this.passwordController.dispose();
    super.dispose();
  }
}

class LoginUISignal {
  final LoginUpdateSignalType signal;
  final String message;

  LoginUISignal(this.signal, {this.message = ""});
}

enum LoginUpdateSignalType {
  LoginSuccess,
  LoginFailure
}