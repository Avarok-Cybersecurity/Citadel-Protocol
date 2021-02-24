import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/register.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/themes/default.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';

import '../utils.dart';

class RegisterScreen extends StatefulWidget {
  static const int IDX = 1;

  RegisterScreen({Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() => _RegisterScreen();
}

const List<String> levels = [
  "High",
  "Very High",
  "Extreme",
  "Ultra",
  "Maximum"
];

class _RegisterScreen extends State<RegisterScreen> {
  final federationAddrController = TextEditingController();
  final usernameController = TextEditingController();
  final passwordController = TextEditingController();
  final password2Controller = TextEditingController();
  final fullnameController = TextEditingController();

  final _formKey = GlobalKey<FormState>();

  bool passwordsMismatch = false;
  bool badAddr = false;

  static const Color ERROR = Color.fromARGB(133, 255, 120, 120);

  String securityLevel = levels.first;

  SendPort sendPort;

  _RegisterScreen() {
    ReceivePort recv = ReceivePort("Register Screen Recv Port");
    this.sendPort = recv.sendPort;
    recv.listen((message) async {
      print("RECV signal to update state");
      await handleUiSignal(message);

      setState(() {});
    });
  }

  Future<void> handleUiSignal(RegisterUISignal signal) async {
    switch (signal.signal) {
      case RegisterUpdateSignalType.RegisterFailure:
        //Utils.popup(context, "Registration failed", signal.message);
      await EasyLoading.dismiss();
      await EasyLoading.showError(signal.message, dismissOnTap: true);
      //await EasyLoading.dismiss();
        break;

      case RegisterUpdateSignalType.RegisterSuccess:
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
              DefaultTextFormField(true, "Federation Address",
                  controller: this.federationAddrController,
                  isFilled: this.badAddr,
                  fillColor: this.badAddr ? ERROR : Colors.white),
              DefaultTextFormField(true, "Full Name",
                  controller: this.fullnameController),
              DefaultTextFormField(true, "Username",
                  controller: this.usernameController),
              DefaultTextFormField(false, "Proposed Password",
                  isPassword: true, controller: this.passwordController),
              DefaultTextFormField(false, "Verify Password",
                  isPassword: true,
                  controller: this.password2Controller,
                  isFilled: this.passwordsMismatch,
                  fillColor: this.passwordsMismatch ? ERROR : Colors.white),
              DropdownButtonFormField(
                value: securityLevel,
                onChanged: (String newValue) {
                  setState(() {
                    this.securityLevel = newValue;
                  });
                },
                items: levels.map<DropdownMenuItem<String>>((String value) {
                  return DropdownMenuItem<String>(
                    value: value,
                    child: Text(value),
                  );
                }).toList(),
                decoration: InputDecoration(labelText: "Security Level"),
              ),
              Padding(
                padding: EdgeInsets.symmetric(vertical: 10),
                child: RaisedButton(
                    child: Text("Register"),
                    color: primary(),
                    textColor: Colors.white,
                    padding: EdgeInsets.fromLTRB(10, 10, 10, 10),
                    onPressed: () {
                      performRegister(this.sendPort);
                    }),
              )
            ],
          ),
        )));
  }

  void performRegister(SendPort sendPort) async {
    print("Federation addr: " + this.federationAddrController.text);
    print("Full name: " + this.fullnameController.text);
    print("Username: " + this.usernameController.text);
    print("Password: " + this.passwordController.text);
    print("Password: " + this.password2Controller.text);
    print("Security setting: " + this.securityLevel);

      this.passwordsMismatch = this.passwordController.text != this.password2Controller.text;

    if (this.passwordController.text != this.password2Controller.text) {
      print("Passwords are NOT equal");
      sendPort.send(RegisterUpdateSignalType.BadPassword);
    } else {
      print("Passwords are equal");
      await EasyLoading.show();

      var socketAddrOpt = await Utils.resolveAddr(this.federationAddrController.text);
      this.badAddr = socketAddrOpt.isEmpty;

      var transfer = RegisterIsolateTransfer(this.federationAddrController.text, this.fullnameController.text, this.usernameController.text, this.passwordController.text, this.securityLevel, this.sendPort);

      if (socketAddrOpt.isPresent) {
        String cmd = "register " +
            socketAddrOpt.value.toString() +
            " --ffi --security " +
            levels.indexOf(this.securityLevel).toString() +
            " --username " +
            this.usernameController.text +
            " --fullname " +
            this.fullnameController.text +
            " --password " +
            this.passwordController.text;

        (await RustSubsystem.bridge.executeCommand(cmd)).ifPresent((kResp) =>
            KernelResponseHandler.handleFirstCommand(kResp,
                handler: RegisterHandler(transfer)));
      } else {

        await Utils.popup(context, "Check Federation Address",
            "Please make sure your address is valid. If using a domain, ensure the server is online");
      }
    }
  }

  @override
  void dispose() {
    this.federationAddrController.dispose();
    this.usernameController.dispose();
    this.passwordController.dispose();
    this.password2Controller.dispose();
    super.dispose();
  }
}

class RegisterIsolateTransfer {
  final String federationAddr;
  final String fullName;
  final String username;
  final String password;
  final String securityLevel;
  final SendPort sendPort;

  RegisterIsolateTransfer(this.federationAddr, this.fullName, this.username,
      this.password, this.securityLevel, this.sendPort);
}

class RegisterUISignal {
  final RegisterUpdateSignalType signal;
  final String message;

  RegisterUISignal(this.signal, {this.message = ""});
}

enum RegisterUpdateSignalType {
  BadPassword,
  BadAddr,
  RegisterSuccess,
  RegisterFailure
}