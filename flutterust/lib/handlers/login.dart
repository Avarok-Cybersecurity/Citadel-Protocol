import 'dart:async';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class LoginHandler implements AbstractHandler {
  final String username;
  final Optional<Credentials> creds;
  final StreamSink<dynamic> sink;

  LoginHandler(this.sink, this.username, this.creds);

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("[Login Handler] Login failed: " + kernelResponse.message);
    this.sink.add(LoginUISignal(LoginUpdateSignalType.LoginFailure, message: kernelResponse.message));
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.Connect)) {
      ConnectResponse resp = kernelResponse.getDSR().value as ConnectResponse;
      if (resp.success) {
        print("[Login Handler] SUCCESS!");
        resp.attachUsername(this.username);
        this.sink.add(LoginUISignal(LoginUpdateSignalType.LoginSuccess, message: kernelResponse.getMessage().orElse("Successfully connected!")));
        HomePage.pushObjectToSession(resp);
        u64 cid = await ClientNetworkAccount.getCidByUsername(this.username).then((value) => value.value);
        if (creds.isPresent) {
          var credentials = creds.value;
          await SecureStorageHandler.saveCredentials(credentials).then((value) => AutoLogin.maybeAddAccount(cid, credentials));
        } else {
          await SecureStorageHandler.deleteCredentialsFor(this.username);
        }
      } else {
        print("[Login Handler] Login failed: " + resp.message);
        this.sink.add(LoginUISignal(LoginUpdateSignalType.LoginFailure, message: resp.message));
      }
      
      return CallbackStatus.Complete;
    } else {
      print("Invalid DSR type!");
      return CallbackStatus.Unexpected;
    }
  }

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }


  static String constructConnectCommand(String username, String password, int securityLevel) {
    return "connect " +
        username +
        " --keep_alive_timeout 900" +
        " --force"
        " -s " + securityLevel.toString() +
        " --password " + password +
        " --ffi" +
        " --fcm-api-key " + Utils.apiKey +
        " --fcm-token " + Utils.nodeClientToken;
  }

}