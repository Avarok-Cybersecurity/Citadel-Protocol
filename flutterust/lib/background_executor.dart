
import 'package:background_fetch/background_fetch.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:flutterust/misc/status_check.dart';

import 'misc/message_send_handler.dart';

class BackgroundExecutor {
  static DateTime programStartTime = DateTime.now();
  static final config = BackgroundFetchConfig(minimumFetchInterval: 15, stopOnTerminate: false, enableHeadless: true, startOnBoot: true, requiredNetworkType: NetworkType.ANY);
  static Future<void> setupBackground() async {
    await BackgroundFetch.configure(config, pollBackground, onTimeout);
    await BackgroundFetch.registerHeadlessTask(headlessExecution);
  }

  static void pollBackground(String taskId) async {
    await poll(taskId, false);
  }

  static Future<void> poll(String taskId, bool headless) async {
    // headless will always run the usual routine
    if (DateTime.now().difference(programStartTime) < Duration(minutes: 10) && !headless) {
      print("Program executed within the last ten minutes; will not check");
      BackgroundFetch.finish(taskId);
      return;
    }

    print("[Background Executor] Running 15m periodic poll for task $taskId");
    await Firebase.initializeApp();
    // make sure bridge is not null
    await RustSubsystem.init();
    //await Utils.configureRTDB(false);

    await checkAccounts();

    // finally, poll any outbound messages that need to be sent
    await MessageSendHandler.poll();

    //Utils.pushNotification("Running background task", taskId);
    BackgroundFetch.finish(taskId);
  }

  static void onTimeout(String taskId) {
    print("Timeout on background task $taskId");
  }
}

/// This function is ran when the app is terminated. Its goal is to check for background messages etc
void headlessExecution(HeadlessTask task) async {
  print("[Headless executor]");
  BackgroundExecutor.poll(task.taskId, true);
}

/// Logs-in to the last logged-in account
Future<void> checkAccounts() async {
  var cids = await ClientNetworkAccount.getAllClients().then((value) => value.orElse([]));

  for (u64 cid in cids) {
    print("[Background Executor] checking $cid ...");
    if (!(await cid.isLocallyConnected())) {
      var cnac = await ClientNetworkAccount.getCnacByCid(cid);
      if (cnac.isPresent) {
        var res = await AutoLogin.initiateAutoLogin(cid, cnac.value.username, backgroundMode: true);
        if (res.success) {
          print("[Background executor] Autologin success");
          if (res.connectResponse.isPresent) {
            ConnectResponse resp = res.connectResponse.value.getDSR().cast().value;
            cnac.value.jwt = Optional.of(resp.jwt.value);
            await cnac.value.sync();
            await checkRTDBForClient(cid, jwt: resp.jwt.value);
          } else {
            // we logged-in, but got no connect response
            await checkRTDBForClient(cid);
          }
        }
      }
    } else {
      await checkRTDBForClient(cid);
    }
  }
}

// Assumes the user is already online. Will get the JWT
Future<void> checkRTDBForClient(u64 cid, { String? jwt }) async {
  UserCredential? creds;
  if (jwt != null) {
    creds = await FirebaseAuth.instance.signInWithCustomToken(jwt);
    print("[Background Executor] Creds obtained: $creds");
  } else {
    var cnac = await ClientNetworkAccount.getCnacByCid(cid);
    if (cnac.isPresent) {
      creds = await FirebaseAuth.instance.signInWithCustomToken(cnac.value.jwt.value);
      print("[Background Executor] Creds obtained: $creds");
    } else {
      print("[Background Executor] unable to find CNAC $cid");
    }
  }

  if (creds != null) {
    print("[Background Executor] Beginning poll of RTDB for $cid ...");
    await Utils.configureRTDB(cid);
    // give time for messages to get processed, then allow the caller to go to the next user
    if (Utils.lastRtdbMessageReceived != null) {
      while (DateTime.now().difference(Utils.lastRtdbMessageReceived!) < Duration(seconds: 15)) {
        await Future.delayed(Duration(seconds: 15));
      }
    }
  } else {
    print("Unable to obtain credentials");
  }
}