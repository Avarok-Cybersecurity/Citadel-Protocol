import 'dart:async';
import 'dart:collection';

import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/login.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:retry/retry.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:flutterust/misc/status_check.dart';

class AutoLogin {
  static HashMap<u64, Credentials> autologinAccounts;
  static const int MAX_RETRY_ATTEMPTS = 12;

  // This should be called at the beginning of program execution once a list of local accounts is loaded
  // This will return immediately after collecting the autologin information
  static Future<void> setupAutologin(List<ClientNetworkAccount> localAccounts) async {
    var autologins = await SecureStorageHandler.getAutologinAccounts(localAccounts);
    autologinAccounts = HashMap();
    for (Credentials creds in autologins) {
      int idx = localAccounts.indexWhere((element) => element.username == creds.username);
      assert (idx != -1);
      autologinAccounts[localAccounts[idx].implicatedCid] = creds;
    }

    print("[AutoLogin] loaded ${autologinAccounts.length} accounts with AutoLogin enabled");
    Future.wait(autologinAccounts.entries.map((e) => initiateAutoLogin(e.key, e.value.username)).toList());
  }

  // since this gets added onLogin, there's no reason to trigger the login subroutine
  static void maybeAddAccount(u64 implicatedCid, Credentials creds) {
    if (autologinAccounts != null) {
      if (!autologinAccounts.containsKey(implicatedCid)) {
        autologinAccounts[implicatedCid] = creds;
        print("[AutoLogin] Added account into the autologin list");
      }
    } else {
      autologinAccounts = HashMap();
      autologinAccounts[implicatedCid] = creds;
    }
  }

  // Calling this won't block the current thread since it must execute an exponential backoff algorithm
  static void onDisconnectSignalReceived(DisconnectResponse dc) async {
    if (autologinAccounts.containsKey(dc.implicated_cid)) {
      String username = autologinAccounts[dc.implicated_cid].username;
      await initiateAutoLogin(dc.implicated_cid, username);
    }
  }

  static Future<void> initiateAutoLogin(u64 implicatedCid, String username) async {
    print("[AutoLogin] disconnect received for $implicatedCid. Will engage reconnection mechanism ...");
    final Credentials creds = autologinAccounts[implicatedCid];
    // initiate exponential backoff ...
    final String connectCmd = LoginHandler.constructConnectCommand(creds.username, creds.password, creds.securityLevel);

    await retry(() async {
      // first step is to always make sure that we're not already connected. It's possible the user logs-in manually between the rest period
      if (await implicatedCid.isLocallyConnected()) {
        print("[AutoLoginHandler] User is already connected; no need to continue autologin ...");
        return;
      }

      StreamController<bool> controller = StreamController();
      var res = await RustSubsystem.bridge.executeCommand(connectCmd).then((value) {
        if (value.isPresent) {
          KernelResponseHandler.handleFirstCommand(value.value, handler: AutoLoginHandler(controller.sink, username), oneshot: false);
          return true;
        } else {
          return false;
        }
      });

      if (res) {
        // 8 seconds is the default in hyxe_net. This high value was needed for connecting to remote high-latency islands, lol
        // It will in 99.9% of the cases terminate far before then unless the server is simply unreachable
        var loginResult =  await controller.stream.first.timeout(Duration(seconds: 8), onTimeout: () async { await controller.close(); throw TimeoutException("Timeout"); });
        await controller.close();

        if (loginResult) {
          print("[AutoLogin] Login success!");
          return;
        } else {
          print("[AutoLogin] Login failure ...");
          throw Exception("Login failed");
        }
      } else {
        throw Exception("Unable to login past stage 1");
      }
    },

        onRetry: (ex) async {
          print("[Exponential Backoff] Will re-attempt connection to $implicatedCid");
        },

        retryIf: (e) => e is TimeoutException || e is Exception,
        maxAttempts: MAX_RETRY_ATTEMPTS
    );
  }
}

class AutoLoginHandler implements AbstractHandler {
  final StreamSink<bool> sink;
  final String username;

  AutoLoginHandler(this.sink, this.username);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    this.sink.add(false);
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.Connect)) {
      print("[AutoLoginHandler] Received expected kernel response");
      ConnectResponse resp = kernelResponse.getDSR().value;
      resp.attachUsername(this.username);
      this.sink.add(resp.success);
      SessionHomeScreenInner.sendPort.send(resp);
      return CallbackStatus.Complete;
    } else {
      print("[AutoLoginHandler] unexpected kernel response $kernelResponse");
      return CallbackStatus.Unexpected;
    }
  }
}