import 'dart:async';
import 'dart:io';

import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/background_executor.dart';
import 'package:flutterust/components/app_retain_widget.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:flutterust/screens/settings.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:scrap/scrap.dart';
import 'package:splashscreen/splashscreen.dart';
import 'components/fade_indexed_stack.dart';
import 'database/database_handler.dart';
import 'screens/register.dart';
import 'themes/default.dart';
import 'package:satori_ffi_parser/types/root/kernel_initiated.dart';

// color: 0xFF9575CD

// TODO: Fix bug where the ticket ID on the adjacent node collides with a ticket ID client-side (A uniqueness problem. May already be fixed with FcmTickets for ~100% of FCM interactions. Client/server interactions will require Tickets to have a boolean flag denoting source)
// TODO: individual deregister + ensure SecureStorage + database wiped
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MaterialApp(
    navigatorObservers: [routeObserver],
    home: Splash(),
    debugShowCheckedModeBanner: false,
    title: "Verisend",
    theme: defaultTheme(),
    builder: EasyLoading.init(),
  ));
}

final RouteObserver<PageRoute> routeObserver = RouteObserver<PageRoute>();

Future<void> loadInit() async {
  await RustSubsystem.init();
  Utils.initNotificationSubsystem();
  Utils.setupDebugListener();
  //Utils.pushNotification("title", "message");
  await Utils.configureFCM();
  await BackgroundExecutor.setupBackground();
  //await Utils.configureRTDB(false);
  print("Done initializing FFI/Rust subsystem ...");
}



class Splash extends StatefulWidget {
  @override
  _MyAppState createState() => new _MyAppState();
}

class _MyAppState extends State<Splash> {

  /// All requires loading should occur here
  Future<Widget> loadFromFuture() async {
    await loadInit();
    return AppRetainWidget(child: HomePage(RustSubsystem.bridge!.isKernelLoaded()));
  }

  @override
  Widget build(BuildContext context) {
    return SplashScreen.future(
        navigateAfterFuture: loadFromFuture(),
        title: new Text('Verisend',
          style: new TextStyle(
            color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 40.0
          ),),
        backgroundColor: primaryColor(),
        styleTextUnderTheLoader: new TextStyle(),
        photoSize: 100.0,
        loaderColor: Colors.white,
    );
  }
}

class RustSubsystem {
  static FFIBridge? bridge;

  // Returns true if pre-initialized
  static Future<void> init({bool force = false}) async {
    if (bridge == null || force) {
      print("Initializing FFI/Rust subsystem ...");
      RustSubsystem.bridge = FFIBridge();
      FFIBridge.setup();
      String databasePath = await DatabaseHandler.databaseKernel();

      await RustSubsystem.bridge!
          .initRustSubsystem(KernelResponseHandler.handleRustKernelRawMessage, databasePath);
    }
  }
}



class HomePage extends StatefulWidget {
  static final List<Widget> screens = [LoginScreen(), const RegisterScreen(false), SessionHomeScreen(), const SettingsScreen()];
  final bool preInitializedKernel;

  HomePage(this.preInitializedKernel, {Key? key}) : super(key: key);

  /// Either an abstract notification of kernel response can be pushed herein
  static void pushObjectToSession(dynamic value) {
    SessionHomeScreen screen = screens[SessionHomeScreen.IDX] as SessionHomeScreen;
    screen.controller.sink.add(value);
  }

  @override
  State<StatefulWidget> createState() => MyHomePage();
}

class MyHomePage extends State<HomePage> with RouteAware {
  int curIdx = LoginScreen.IDX;

  @override
  void initState() {
    super.initState();
    this.onStart();
    Utils.checkPowerManager(); //prev had await
  }

  Future<void> _maybeResyncClients() async {
    if ((await ClientNetworkAccount.resyncClients()) == 0) {
      Navigator.push(context, Utils.createDefaultRoute(const RegisterScreen(true)));
    }
  }

  void onStart() async {
    AwesomeNotifications().actionStream.listen((receivedNotification) async {
      print("[Notification] recv payload: ${receivedNotification.payload}");

      if (receivedNotification.payload != null) {
        Optional<AbstractPushNotification> apn = AbstractPushNotification.tryFromMap(receivedNotification.payload!.map((key, value) => MapEntry(key, value.toString())));

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
      } else {
        print("Null route payload. Will not continue");
      }
    });

    if (this.widget.preInitializedKernel) {
      print("Kernel pre-initialized. Skipping ordinary init phase ...");
      await this._maybeResyncClients();
      LoginScreen screen = HomePage.screens[LoginScreen.IDX] as LoginScreen;
      screen.coms.sink.add(KernelInitiated());
      return;
    }

    try {
      await Utils.kernelInitiatedSink.stream.first.timeout(Duration(seconds: 7)).then((value) async {
        LoginScreen screen = HomePage.screens[LoginScreen.IDX] as LoginScreen;
        screen.coms.sink.add(value);

        await this._maybeResyncClients();

        await Utils.kernelInitiatedSink.close();
      });

    } catch(_) {
      await Utils.kernelInitiatedSink.close();

      // The only reason this happens is really if NTP can't be reached, usually implying the user's internet is down
      if (Platform.isAndroid) {
        EasyLoading.showError("Unable to establish kernel connection. Internet may be down. Closing in 4 seconds", dismissOnTap: true);
        Future.delayed(Duration(seconds: 4), () => SystemChannels.platform.invokeMethod('SystemNavigator.pop'));
      } else if (Platform.isIOS) {
        EasyLoading.showError("Unable to establish kernel connection. Internet may be down. You may now close the app", dismissOnTap: true);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text("Verisend")),
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
  
  ListTile createMenuTile(final int idx, {Widget? leading}) {
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
