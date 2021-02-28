import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:flutter/material.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/components/app_retain_widget.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:flutterust/utils.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/dsr/get_accounts_response.dart';
import 'package:scrap/scrap.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'components/fade_indexed_stack.dart';
import 'database_handler.dart';
import 'screens/register.dart';
import 'themes/default.dart';

// color: 0xFF9575CD

// TODO: Fix bug where the ticket ID on the adjacent node collides with a ticket ID client-side (may be fixed with FcmTickets)
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  //await RustSubsystem.init();
  await RustSubsystem.init();
  Utils.initNotificationSubsystem();
  Utils.pushNotification("title", "message");
  await Utils.configureFCM();
  print("Done initializing FFI/Rust subsystem ...");
  runApp(MyApp());
}

class RustSubsystem {
  static FFIBridge bridge;

  static Future<void> init() async {
    if (bridge == null) {
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

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: APP_TITLE,
      theme: defaultTheme(),
      home: AppRetainWidget(
        child: HomePage(APP_TITLE),
      ),
      builder: EasyLoading.init(),
    );
  }
}

class HomePage extends StatefulWidget {
  final String title;

  HomePage(this.title, {Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() => MyHomePage(this.title);
}

class MyHomePage extends State<HomePage> {
  final String title;
  int curIdx = LoginScreen.IDX;

  MyHomePage(this.title) {
    print("CONSTRUCTING HOME PAGE");
    // TODO: on first run, set to register instead of login screen
    this.curIdx = LoginScreen.IDX;

    AwesomeNotifications().actionStream.listen((receivedNotification) {
      print("~~~ Received notification route ~~~");
      /*Navigator.of(context).pushNamed(
              '/NotificationPage',
              arguments: { id: receivedNotification.id } // your page params. I recommend to you to pass all *receivedNotification* object
          );*/
      // TODO: Handle routes for notifications
    });
  }

  @override
  void initState() {
    super.initState();
    this.onStart();
  }

  void onStart() async {
    (await RustSubsystem.bridge.executeCommand("list-accounts"))
        .ifPresent((kResp) {
      kResp.getDSR().ifPresent((dsr) async {
        if (dsr is GetAccountsResponse) {
          print("Found " + dsr.cids.length.toString() + " local accounts");
          if (dsr.cids.isEmpty) {
            this.curIdx = RegisterScreen.IDX;
          } else {
            await DatabaseHandler.clearDatabase();
            DatabaseHandler.insertClients(zip([dsr.cids, dsr.usernames, dsr.full_names, dsr.is_personals, dsr.creation_dates]).map((e) => ClientNetworkAccount(e[0], e[1], e[2], e[3], e[4])).toList(growable: false));
            var username = await ClientNetworkAccount.getCnacByCid(u64.tryFrom("10810377489972841717").value);
            print("username of cid: " + username.toString());
          }
        }
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(title)),
      body: FadeIndexedStack(
        children: <Widget>[
          LoginScreen(),
          RegisterScreen(),
          SessionHomeScreen()
        ],
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
            ListTile(
              // login screen
              title: Text(sidebarMenuItems[LoginScreen.IDX]),
              onTap: () {
                // Update the state of the app
                // ...
                // Then close the drawer
                Navigator.pop(context);
                if (this.curIdx != LoginScreen.IDX) {
                  setState(() {
                    this.curIdx = LoginScreen.IDX;
                  });
                }
              },
            ),
            ListTile(
              title: Text(sidebarMenuItems[RegisterScreen.IDX]),
              onTap: () {
                // Update the state of the app
                // ...
                // Then close the drawer
                Navigator.pop(context);
                if (this.curIdx != RegisterScreen.IDX) {
                  setState(() {
                    this.curIdx = RegisterScreen.IDX;
                  });
                }
              },
            ),
            ListTile(
              title: Text(sidebarMenuItems[SessionHomeScreen.IDX]),
              onTap: () {
                // Update the state of the app
                // ...
                // Then close the drawer
                Navigator.pop(context);
                if (this.curIdx != SessionHomeScreen.IDX) {
                  setState(() {
                    this.curIdx = SessionHomeScreen.IDX;
                  });
                }
              },
            ),
          ],
        ),
      ),
    );
  }
}

const List<String> sidebarMenuItems = ["Login", "Register", "Sessions"];
