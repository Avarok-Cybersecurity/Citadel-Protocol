import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:flutter/material.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/components/app_retain_widget.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:flutterust/screens/session/session_subscreens/mutual_peer.dart';
import 'package:flutterust/screens/session/session_subscreens/mutuals.dart';
import 'package:flutterust/screens/session/session_subscreens/peer_list.dart';
import 'package:flutterust/screens/session/session_subscreens/post_register_invitation.dart';
import 'package:flutterust/screens/settings.dart';
import 'package:flutterust/utils.dart';
import 'package:scrap/scrap.dart';
import 'components/fade_indexed_stack.dart';
import 'database/database_handler.dart';
import 'screens/register.dart';
import 'themes/default.dart';

// color: 0xFF9575CD

// TODO: Fix bug where the ticket ID on the adjacent node collides with a ticket ID client-side (may be fixed with FcmTickets)
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  //await RustSubsystem.init();
  await RustSubsystem.init();
  Utils.initNotificationSubsystem();
  //Utils.pushNotification("title", "message");
  await Utils.configureFCM();
  print("Done initializing FFI/Rust subsystem ...");
  runApp(MyApp());
}

class RustSubsystem {
  static FFIBridge bridge;

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
  final Widget main = AppRetainWidget(child: HomePage(APP_TITLE));
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
        LoginScreen.routeName: (context) => const LoginScreen(),
        SessionHomeScreen.routeName: (context) => SessionHomeScreen()
      },
    );
  }
}

class HomePage extends StatefulWidget {
  final String title;
  static final List<Widget> screens = [const LoginScreen(), const RegisterScreen(false), SessionHomeScreen(), const SettingsScreen()];

  HomePage(this.title, {Key key}) : super(key: key);

  static void pushNotificationToSession(AbstractNotification notification) {
    SessionHomeScreen screen = screens[SessionHomeScreen.IDX];
    screen.sendPort.send(notification);
  }

  @override
  State<StatefulWidget> createState() => MyHomePage(this.title);
}

class MyHomePage extends State<HomePage> {
  final String title;
  int curIdx = LoginScreen.IDX;

  MyHomePage(this.title) {
    print("CONSTRUCTING HOME PAGE");
  }

  @override
  void initState() {
    super.initState();
    this.onStart();
  }

  void onStart() async {
    AwesomeNotifications().actionStream.listen((receivedNotification) {
      String hashcode = receivedNotification.payload["widgetHashcode"];

      Widget widget = Utils.notificationPayloads[hashcode];

      print("~~~ Received notification route to ${widget.toStringShort()} ~~~");
      Navigator.push(context, Utils.createDefaultRoute(widget));
    });

    if ((await ClientNetworkAccount.resyncClients()) == 0) {
      Navigator.push(context, Utils.createDefaultRoute(const RegisterScreen(true)));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(title)),
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
