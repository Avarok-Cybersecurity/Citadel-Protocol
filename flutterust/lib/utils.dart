import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_database/firebase_database.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/active_message_broadcast.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/themes/default.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/socket_addr.dart';
import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:google_https_dns/library.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:scrap/scrap.dart';
import 'package:satori_ffi_parser/types/root/kernel_initiated.dart';
import 'package:android_power_manager/android_power_manager.dart';

import 'database/database_handler.dart';

const int DEFAULT_PORT = 25021;

class Utils {
  static Future<Optional<SocketAddr>> resolveAddr(String addr) async {
    try {
      var basicIP = InternetAddress.tryParse(addr);
      if (basicIP != null) {
        return Optional.of(SocketAddr(basicIP, DEFAULT_PORT));
      }

      var socket = SocketAddr.tryFrom(addr);
      if (socket.isPresent) {
        return socket;
      }

      // Last option is either addr in the format of "google.com", or "google.com:1234"
      List<String> pieces = addr.split(":");
      if (pieces.length > 2) {
        return Optional.empty();
      }

      final result = await GoogleSecureDnsClient.getIpOf(pieces[0]);
      if (result.isEmpty) {
        print("DNS returned no items");
        return Optional.empty();
      }

      // TODO: Make a selection screen for the list of IPs
      InternetAddress? ip = InternetAddress.tryParse(result.first);
      if (ip == null) {
        return Optional.empty();
      }

      if (pieces.length == 1) {
        // "type of "google.com", and use default port
        return Optional.of(SocketAddr(ip, DEFAULT_PORT));
      } else {
        // type of "google.com:1234", custom port
        return SocketAddr.tryFromUncheckedPort(ip, pieces[1]);
      }
    } catch(_) {
      return Optional.empty();
    }
  }

  static Future<void> popup(BuildContext context, String title, String message) async {
    return showDialog<void>(
      context: context,
      barrierDismissible: false, // user must tap button!
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(title),
          content: SingleChildScrollView(
            child: ListBody(
              children: <Widget>[
                Text(message)
              ],
            ),
          ),
          actions: <Widget>[
            TextButton(
              child: Text('OK'),
              onPressed: () {
                Navigator.of(context).pop();
              },
            ),
          ],
        );
      },
    );
  }

  static const NOTIFICATION_CHANNEL = "primary_channel";

  // On android, Java automatically sets up the notification subsystem
  static void initNotificationSubsystem() {
      AwesomeNotifications().initialize(
          //'resource://drawable/ic_launcher',
        null,
          [
            NotificationChannel(
                channelKey: NOTIFICATION_CHANNEL,
                channelName: 'Verisend| Messages',
                channelDescription: 'Notification channel for messages and events',
                defaultColor: primaryColor(),
                ledColor: primaryColor()
            )
          ]
      );

      AwesomeNotifications().isNotificationAllowed().then((isAllowed) {
        if (!isAllowed) {
          // Insert here your friendly dialog box before call the request method
          // This is very important to not harm the user experience
          AwesomeNotifications().requestPermissionToSendNotifications();
        }
      });
  }

  static int idx = 0;

  static void pushNotification(String title, String message, { int? id, AbstractPushNotification? apn }) {
      AwesomeNotifications().createNotification(
          content: NotificationContent(
              id: id ?? idx++,
              channelKey: NOTIFICATION_CHANNEL,
              title: title,
              body: message,
              payload: apn?.getPreservableMap()
          )
      );
  }

  static Future<void> checkPowerManager() async {
    var res = await AndroidPowerManager.isIgnoringBatteryOptimizations;
    if (res != null) {
      if (res) {
        return;
      }
    }

    await AndroidPowerManager.requestIgnoreBatteryOptimizations();
  }

  static FirebaseMessaging firebase = FirebaseMessaging.instance;
  static String nodeClientToken = "";
  static const String apiKey = "AAAAsdc2buM:APA91bFGIgSp9drZGpM6rsTVWD_4A28QZVjBG9ty0ijwXn0k-peMNiivzCuSzojR7ESN13txcD7pZMyYJC_LPdjRk56EdXnUfIYDgVVbTN8VmWiVd82uJv2kEgcoGL-Flh1HXWZlVSf8";

  static Future<void> configureFCM() async {
    await Firebase.initializeApp();
    FirebaseMessaging.onMessage.listen(onFcmMessageReceived);
    FirebaseMessaging.onBackgroundMessage(onFcmMessageReceived);

    var key = await firebase.getToken();
    if (key == null) {
      print("Firebase token returned null");
      return;
    }

    nodeClientToken = key;

    print("[FCM] Token: " + nodeClientToken.toString());
    firebase.onTokenRefresh.listen((clientRegId) {
      print("[FCM] Received new token: " + clientRegId);
      nodeClientToken = clientRegId;
      // TODO: Implement update mechanism
    });
  }

  static HashMap<u64, LeafListener>? listeners;

  static DateTime? lastRtdbMessageReceived;
  /// This should be called periodically as required
  static Future<void> configureRTDB(u64 newlyLoggedInUser) async {
    // for purposes of allowing time for messages to come-thru, set the last rtdb message time as now
    lastRtdbMessageReceived = DateTime.now();

      if (listeners == null) {
        listeners = HashMap();
      }

      var res = await FirebaseDatabase.instance.setPersistenceEnabled(true);
      // we need to listen to a series of leafs. Listen on each user logged-in
      //List<u64> accounts = await ClientNetworkAccount.getAllClients().then((value) => value.orElse([]));
      print("[RTDB handler] SPE Result $res");

      //for (u64 cid in accounts) {
          var ref = FirebaseDatabase.instance.reference().child("users").child(newlyLoggedInUser.toString());
          await ref.keepSynced(true);

          // ignore: cancel_subscriptions
          var listener = ref.onValue.listen((event) async {
            print("[RTDB] Data received: KEY: ${event.snapshot.key}. prev sibling: ${event.previousSiblingKey}. VALUE: ${event.snapshot.value}");
            // await ref.child(event.snapshot.key).remove();
            // TODO: This expects only packets. In the future, make it accept more
            var key = event.snapshot.key;
            Map<String, dynamic> tree = new Map<String, dynamic>.from(event.snapshot.value);
            print("Outer tree: $tree");
            for (MapEntry<String, dynamic> superPeerTreeUncast in tree.entries) {
              Map<String, dynamic> superPeerTree = new Map<String, dynamic>.from(superPeerTreeUncast.value);
              print("Super peer tree: \n$superPeerTree\n");
              for (MapEntry<String, dynamic> peerTreeUncast in superPeerTree.entries) {
                  Map<String, dynamic> peerTree = new Map<String, dynamic>.from(peerTreeUncast.value);
                  print("Peer tree: \n$peerTree\n");

                  if (peerTree.containsKey("packets")) {
                    Map<String, dynamic> packetsTree = new Map<String, dynamic>.from(peerTree["packets"]);
                    for (MapEntry<String, dynamic> entry in packetsTree.entries) {
                      Map<String, dynamic> newPacketTree = new Map<String, dynamic>.from(entry.value);
                      String json = newPacketTree["inner"];

                      await processJsonPacket(json);
                      // delete AFTER being processed
                      await ref.child("peers").child(peerTreeUncast.key).child("packets").child(entry.key).remove();
                      lastRtdbMessageReceived = DateTime.now();
                    }

                  }
              }
            }
          });

          listeners![newlyLoggedInUser] = LeafListener(listener, ref);
          print("Added RTDB listener for $newlyLoggedInUser");
      //}
  }

  static String prevPacket = "";

  static Future<dynamic> onFcmMessageReceived(RemoteMessage message) async {
    String json = message.data["inner"];

    print("[FCM] Received FCM message! " + json);
      //pushNotification("Received a FCM message", json);
    if (prevPacket == json) {
      print("Duplicate FCM packet recv'd (skipping)");
      return;
    } else {
      prevPacket = json;
    }

    await processJsonPacket(json);
  }

  static Future<void> processJsonPacket(String json) async {
    String databasePath = await DatabaseHandler.databaseKernel();

    // subsystem may be null if we're in the background isolate
    if (RustSubsystem.bridge == null) {
      print("[FCM] RustSubsystem not loaded. Will load *basic* FFI connection ...");
      RustSubsystem.bridge = FFIBridge();
      FFIBridge.setup();
    }

    print("[FCM] awaiting kernel response ...");
    Optional<KernelResponse> kResp = await RustSubsystem.bridge!.handleFcmMessage(json, databasePath);
    print("[FCM] response received. Is valid? " + kResp.isPresent.toString());
    // Here, we delegate the response to the default handler
    kResp.ifPresent(KernelResponseHandler.handleRustKernelMessage);
  }

  static Route createDefaultRoute(final Widget widget) {
    return PageRouteBuilder(
        pageBuilder: (context, animation, secondaryAnimation) => widget,
        transitionsBuilder: (context, animation, secondaryAnimation, child) {
          return FadeTransition(
            opacity: animation,
            child: child,
          );
        }
    );
  }

  // This is only for when the screen is on and a user has a messaging screen open
  static final MessageStreamer broadcaster = MessageStreamer();

  static void setupDebugListener() {
    broadcaster.stream.stream.listen((event) {
      print("[Broadcaster Default Sink] Received message: ${event.message}");
    });
  }

  static StreamController<KernelInitiated> kernelInitiatedSink = StreamController();

  static Optional<u64> currentlyOpenedMessenger = Optional.empty();
}

class LeafListener {
  final StreamSubscription listener;

  LeafListener(this.listener, this.ref);

  final DatabaseReference ref;

}