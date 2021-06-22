import 'dart:async';
import 'dart:collection';

import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/login.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:optional/optional.dart';
import 'package:retry/retry.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:flutterust/misc/status_check.dart';

class AutoLogin {
  static HashMap<u64, Credentials>? autologinAccounts;
  static const int MAX_RETRY_ATTEMPTS = 12;

  // This should be called at the beginning of program execution once a list of local accounts is loaded
  // This will return immediately after collecting the autologin information
  static Future<void> setupAutologin(List<ClientNetworkAccount> localAccounts) async {
    var autologins = await SecureStorageHandler.getAutologinAccounts(localAccounts);
    autologinAccounts = HashMap();
    for (Credentials creds in autologins) {
      int idx = localAccounts.indexWhere((element) => element.username == creds.username);
      assert (idx != -1);
      autologinAccounts![localAccounts[idx].implicatedCid] = creds;
    }

    print("[AutoLogin] loaded ${autologinAccounts!.length} accounts with AutoLogin enabled");
    Future.wait(autologinAccounts!.entries.map((e) => initiateAutoLogin(e.key, e.value.username)).toList());
  }

  // since this gets added onLogin, there's no reason to trigger the login subroutine
  static void maybeAddAccount(u64 implicatedCid, Credentials creds) {
    if (autologinAccounts != null) {
      if (!autologinAccounts!.containsKey(implicatedCid)) {
        autologinAccounts![implicatedCid] = creds;
        print("[AutoLogin] Added account into the autologin list");
      }
    } else {
      autologinAccounts = HashMap();
      autologinAccounts![implicatedCid] = creds;
    }
  }

  // Calling this won't block the current thread since it must execute an exponential backoff algorithm
  static void onDisconnectSignalReceived(DisconnectResponse dc) async {
    if (autologinAccounts!.containsKey(dc.implicatedCid)) {
      String username = autologinAccounts![dc.implicatedCid]!.username;
      await initiateAutoLogin(dc.implicatedCid, username);
    }
  }

  /// If supplied, username needs to belong to the implicatedCid
  static Future<Optional<KernelResponse>> executeCommandRequiresConnected(u64 implicatedCid, String command, { String? username }) async {
    String? uname;

    if (username != null) {
      uname = username;
    } else {
      var unameOpt = await ClientNetworkAccount.getUsernameByCid(implicatedCid);
      if (unameOpt.isEmpty) {
        print("Username for $implicatedCid not found!");
        return Optional.empty();
      }

      uname = unameOpt.value;
    }

    if (await resync()) {
      if (await initiateAutoLogin(implicatedCid, uname)) {
        print("Account successfully logged-in; will now execute enqueued command ...");
        return await RustSubsystem.bridge!.executeCommand(command);
      } else {
        return Optional.empty();
      }
    } else {
      print("Error: resync failed");
      return Optional.empty();
    }
  }

  static Future<bool> resync() async {
    final StreamController<Optional<KernelResponse>> controller = StreamController();
    await RustSubsystem.bridge!.executeCommand("resync").then((value) => value.ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp, handler: ResyncHandler(controller.sink))));
    Optional<KernelResponse> resyncResult = await controller.stream.first.timeout(Duration(seconds: 3), onTimeout: () async { await controller.close(); throw TimeoutException("Timeout"); });
    await controller.close();

    return resyncResult.isPresent;
  }

  static Future<bool> initiateAutoLogin(u64 implicatedCid, String username) async {
    print("[AutoLogin] Engaging reconnection mechanism ...");
    final Credentials? creds = autologinAccounts![implicatedCid];

    if (creds == null) {
      print("implicated CID is not in the autologin hashmap");
      return false;
    }

    // first, resync the kernel
    if (await resync()) {
      // initiate exponential backoff ...
      final String connectCmd = LoginHandler.constructConnectCommand(creds.username, creds.password, creds.securityLevel);

      // Returns true if end-result is connected, regaurdless if connection attempts required
      var future = retry(() async {
        // first step is to always make sure that we're not already connected
        if (await implicatedCid.isLocallyConnected()) {
          print("[AutoLoginHandler] User is already connected; no need to continue autologin ...");
          return true;
        }

        // Make sure the account exists in the local db
        if (!await ClientNetworkAccount.getCnacByCid(implicatedCid).then((value) => value.isPresent)) {
          print("Account does not exist locally. Will not connect (newly registered?)");
          return false;
        }



        final StreamController<bool> controller = StreamController();
        var res = await RustSubsystem.bridge!.executeCommand(connectCmd).then((value) {
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
            return true;
          } else {
            print("[AutoLogin] Login failure ...");
            throw Exception("Login failed");
          }
        } else {
          throw Exception("Unable to login past stage 1");
        }
      },

          onRetry: (ex) async {
            print("[Exponential Backoff] Will re-attempt connection to $implicatedCid. Ex: $ex");
          },

          maxDelay: Duration(minutes: 10),

          retryIf: (e) => e is TimeoutException || e is Exception,
          maxAttempts: MAX_RETRY_ATTEMPTS
      );

      try {
        return await future;
      } catch(_) {
        return false;
      }
    } else {
      print("Error: resync failed");
      return false;
    }
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
      ConnectResponse resp = kernelResponse.getDSR().value as ConnectResponse;
      resp.attachUsername(this.username);

      try {
        this.sink.add(resp.success);
      } catch(_) {
        print("Autologin Sink closed w/ error");
      }

      HomePage.pushObjectToSession(resp);
      return CallbackStatus.Complete;
    } else {
      print("[AutoLoginHandler] unexpected kernel response $kernelResponse");
      return CallbackStatus.Unexpected;
    }
  }
}

class ResyncHandler implements AbstractHandler {
  final StreamSink<Optional<KernelResponse>> sink;

  ResyncHandler(this.sink);


  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    this.sink.add(Optional.empty());
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    this.sink.add(Optional.of(kernelResponse));
    return CallbackStatus.Complete;
  }

}