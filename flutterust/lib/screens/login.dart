import 'dart:async';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/login.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/root/kernel_initiated.dart';

class LoginScreen extends StatefulWidget {
  static const String routeName = "/login";
  static const int IDX = 0;
  final StreamController<dynamic> coms = StreamController();

  LoginScreen({Key? key}) : super(key: key);

  @override
  State<StatefulWidget> createState() => _LoginScreen();
}

class _LoginScreen extends State<LoginScreen> {
  final usernameController = TextEditingController();
  final passwordController = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  static const List<String> levels = ["High", "Very High", "Extreme", "Ultra", "Maximum"];
  String securityLevel = levels.first;
  bool autoLogin = true;
  bool loginButtonEnabled = false;

  late final StreamSubscription<dynamic> coms;

  @override
  void initState() {
    super.initState();

    this.coms = this.widget.coms.stream.listen((message) async {
      print("RECV signal to update state");
      if (message is KernelInitiated) {
        this.loginButtonEnabled = true;
      } else {
        await handleUISignal(message);
      }

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

                onChanged: (String? newValue) {
                  if (newValue != null) {
                    setState(() {
                      this.securityLevel = newValue;
                    });
                  }
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

              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    Text("Auto login"),
                    Checkbox(
                      value: this.autoLogin,
                      onChanged: (newValue) {
                        if (newValue != null) {
                          setState(() {
                            this.autoLogin = newValue;
                          });
                        }
                      },
                    )
                  ],
                ),

              Padding(
                padding: EdgeInsets.symmetric(vertical: 10),
                child: this.loginButtonEnabled ? ElevatedButton(
                  child: Text("Connect"),
                  onPressed: () => performLogin(),
                ) : CircularProgressIndicator(),
              )
            ],
          ),
        )
      )
    );
  }

  void performLogin() async {
    FocusManager.instance.primaryFocus?.unfocus();
    await EasyLoading.show();
    print("Username: " + this.usernameController.text);
    print("Password: " + this.passwordController.text);
    print("Security setting: " + this.securityLevel);
    print("AutoLogin: $autoLogin");

    this._formKey.currentState?.save();
    String username = this.usernameController.text;
    String password = this.passwordController.text;
    int securityLevel = levels.indexOf(this.securityLevel);

    Optional<Credentials> creds = this.autoLogin ? Optional.of(Credentials(username, password, securityLevel)) : Optional.empty();

    var cmd = LoginHandler.constructConnectCommand(username, password, securityLevel);

    print("Executing: " + cmd);
    (await RustSubsystem.bridge!.executeCommand(cmd))
    .ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp, handler: LoginHandler(this.widget.coms.sink, this.usernameController.text, creds)));
  }

  @override
  void dispose() {
    super.dispose();
    this.usernameController.dispose();
    this.passwordController.dispose();
    this.coms.cancel();
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