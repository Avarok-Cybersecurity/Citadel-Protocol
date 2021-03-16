import 'dart:async';
import 'dart:io';

import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/components/app_retain_widget.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:flutterust/screens/settings.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:scrap/scrap.dart';
import 'components/fade_indexed_stack.dart';
import 'screens/register.dart';
import 'themes/default.dart';
import 'package:satori_ffi_parser/types/root/kernel_initiated.dart';

// color: 0xFF9575CD

// TODO: Fix bug where the ticket ID on the adjacent node collides with a ticket ID client-side (may be fixed with FcmTickets)
// TODO: Add a call on init checking for kernel health just incase the kernel is already running and the primary screen is rebuilt
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  //await RustSubsystem.init();
  await RustSubsystem.init();
  Utils.initNotificationSubsystem();
  Utils.setupDebugListener();
  //Utils.pushNotification("title", "message");
  await Utils.configureFCM();
  print("Done initializing FFI/Rust subsystem ...");
  runApp(MyApp(AppRetainWidget(child: HomePage(RustSubsystem.bridge.isKernelLoaded()))));
}

class RustSubsystem {
  static FFIBridge bridge;

  // Returns true if pre-initialized
  static Future<void> init({bool force = false}) async {
    if (bridge == null || force) {
      print("Initializing FFI/Rust subsystem ...");
      RustSubsystem.bridge = FFIBridge();
      FFIBridge.setup();

      await RustSubsystem.bridge
          .initRustSubsystem(KernelResponseHandler.handleRustKernelRawMessage);
    }
  }
}

class MyApp extends StatelessWidget {
  static const APP_TITLE = 'Verisend';
  final Widget main;

  const MyApp(this.main);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: APP_TITLE,
      theme: defaultTheme(),
      builder: EasyLoading.init(),
      //home: main,
      initialRoute: '/',
      routes: {
        '/': (context) => main,

        RegisterScreen.routeName: (context) => const RegisterScreen(false),
        LoginScreen.routeName: (context) => LoginScreen(),
        SessionHomeScreen.routeName: (context) => SessionHomeScreen()
      },
    );
  }
}

class HomePage extends StatefulWidget {
  static final List<Widget> screens = [LoginScreen(), const RegisterScreen(false), SessionHomeScreen(), const SettingsScreen()];
  final bool preInitializedKernel;

  HomePage(this.preInitializedKernel, {Key key}) : super(key: key);

  /// Either an abstract notification of kernel response can be pushed herein
  static void pushObjectToSession(dynamic value) {
    SessionHomeScreen screen = screens[SessionHomeScreen.IDX];
    screen.controller.sink.add(value);
  }

  @override
  State<StatefulWidget> createState() => MyHomePage();
}

class MyHomePage extends State<HomePage> {
  int curIdx = LoginScreen.IDX;

  @override
  void initState() {
    super.initState();
    this.onStart();
  }

  Future<void> _maybeResyncClients() async {
    if ((await ClientNetworkAccount.resyncClients()) == 0) {
      Navigator.push(context, Utils.createDefaultRoute(const RegisterScreen(true)));
    }
  }

  void onStart() async {
    AwesomeNotifications().actionStream.listen((receivedNotification) async {
      print("[Notification] recv payload: ${receivedNotification.payload}");

      Optional<AbstractPushNotification> apn = AbstractPushNotification.tryFromMap(receivedNotification.payload.map((key, value) => MapEntry(key, value.toString())));

      if (apn.isPresent) {
        Optional<Widget> widget = await apn.value.constructWidget();
        if (widget.isPresent) {
          Navigator.push(context, Utils.createDefaultRoute(widget.value));
        } else {
          print("Widget not specified for the APN");
        }
      } else {
        print("Navigator could not route b/c APN did not compile from map");
      }
    });

    if (this.widget.preInitializedKernel) {
      print("Kernel pre-initialized. Skipping ordinary init phase ...");
      await this._maybeResyncClients();
      LoginScreen screen = HomePage.screens[LoginScreen.IDX];
      screen.coms.sink.add(KernelInitiated());
      return;
    }

    StreamController<KernelInitiated> initController = StreamController();
    Utils.kernelInitiatedSink = initController.sink;

    try {
      await initController.stream.first.timeout(Duration(seconds: 7)).then((value) async {
        LoginScreen screen = HomePage.screens[LoginScreen.IDX];
        screen.coms.sink.add(value);

        await this._maybeResyncClients();

        await Utils.kernelInitiatedSink.close();
        await initController.close();
      });

    } catch(_) {
      await Utils.kernelInitiatedSink.close();
      await initController.close();

      // The only reason this happens is really if NTP can't be reached, usually implying the user's internet is down
      if (Platform.isAndroid) {
        EasyLoading.showError("Unable to establish kernel connection. Please try restarting your phone. Closing in 4 seconds", dismissOnTap: true);
        Future.delayed(Duration(seconds: 4), () => SystemChannels.platform.invokeMethod('SystemNavigator.pop'));
      } else if (Platform.isIOS) {
        EasyLoading.showError("Unable to establish kernel connection. Please try restarting your phone. You may now close the app", dismissOnTap: true);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(MyApp.APP_TITLE)),
      body: FadeIndexedStack(
        children: HomePage.screens,
        index: curIdx,
      ),
      drawer: Drawer(
        // Add a ListView to the drawer. This ensures the user can scroll
        // through the options in the drawer if there isn't enough vertical
        // space to fit everything.
        child: ListView(
          // Important: Remove any padding from the ListView.
          padding: EdgeInsets.zero,
          children: <Widget>[
            DrawerHeader(
              child: Text('Menu', style: TextStyle(color: Colors.white)),
              decoration: BoxDecoration(
                color: primary(),
              ),
            ),
            createMenuTile(LoginScreen.IDX, leading: Icon(Icons.login)),
            createMenuTile(RegisterScreen.IDX, leading: Icon(Icons.app_registration)),
            createMenuTile(SessionHomeScreen.IDX, leading: Icon(Icons.list)),
            createMenuTile(SettingsScreen.IDX, leading: Icon(Icons.settings))
          ],
        ),
      ),
    );
  }
  
  ListTile createMenuTile(final int idx, {Widget leading}) {
    return ListTile(
      leading: leading,
      title: Text(sidebarMenuItems[idx]),
      onTap: () {
        // Update the state of the app
        // ...
        // Then close the drawer
        Navigator.pop(context);
        if (this.curIdx != idx) {
          setState(() {
            this.curIdx = idx;
          });
        }
      },
    );
  }
}

const List<String> sidebarMenuItems = ["Login", "Register", "Sessions", "Device Settings"];
