import 'dart:async';
import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'package:dns/dns.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/active_message_broadcast.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/themes/default.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/socket_addr.dart';
import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:scrap/scrap.dart';
import 'package:satori_ffi_parser/types/root/kernel_initiated.dart';

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

      final client = HttpDnsClient.google();

      final result = await client.lookup(pieces[0]);
      if (result.isEmpty) {
        print("DNS returned no items");
        return Optional.empty();
      }

      InternetAddress ip = InternetAddress.fromRawAddress(Uint8List.fromList(result.first.toImmutableBytes()));

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

  static void pushNotification(String title, String message, { int id, AbstractPushNotification apn }) {
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

  static FirebaseMessaging firebase = FirebaseMessaging.instance;
  static String nodeClientToken = "";
  static const String apiKey = "AAAAsdc2buM:APA91bFGIgSp9drZGpM6rsTVWD_4A28QZVjBG9ty0ijwXn0k-peMNiivzCuSzojR7ESN13txcD7pZMyYJC_LPdjRk56EdXnUfIYDgVVbTN8VmWiVd82uJv2kEgcoGL-Flh1HXWZlVSf8";

  static Future<void> configureFCM() async {
    await Firebase.initializeApp();
    FirebaseMessaging.onMessage.listen(onFcmMessageReceived);
    FirebaseMessaging.onBackgroundMessage(onFcmMessageReceived);

    nodeClientToken = await firebase.getToken();
    print("[FCM] Token: " + nodeClientToken);
    firebase.onTokenRefresh.listen((clientRegId) {
      print("[FCM] Received new token: " + clientRegId);
      nodeClientToken = clientRegId;
    });
  }

  static Future<dynamic> onFcmMessageReceived(RemoteMessage message) async {
    String json = message.data["inner"];

    print("[FCM] Received FCM message! " + json);
      //pushNotification("Received a FCM message", json);

      // subsystem may be null if we're in the background isolate
      if (RustSubsystem.bridge == null) {
        print("[FCM] RustSubsystem not loaded. Will load *basic* FFI connection ...");
        RustSubsystem.bridge = FFIBridge();
        FFIBridge.setup();
      }

      print("[FCM] awaiting kernel response ...");
      Optional<KernelResponse> kResp = await RustSubsystem.bridge.handleFcmMessage(json);
      print("[FCM] response received. Is valid? " + kResp.isPresent.toString());
      // Here, we delegate the response to the default handler
      kResp.ifPresent(KernelResponseHandler.handleRustKernelMessage);
    // Or do other work.
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

  static StreamSink<KernelInitiated> kernelInitiatedSink;

  static Optional<u64> currentlyOpenedMessenger = Optional.empty();
}
