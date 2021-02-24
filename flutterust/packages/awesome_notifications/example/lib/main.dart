import 'package:flutter/material.dart';
import 'package:awesome_notifications_example/routes.dart';
import 'package:awesome_notifications/awesome_notifications.dart';
import 'package:awesome_notifications_example/models/media_model.dart';
import 'package:awesome_notifications_example/utils/media_player_central.dart';

void main() async {

  AwesomeNotifications().initialize(
    'resource://drawable/res_app_icon',
    [
      NotificationChannel(
          channelKey: 'basic_channel',
          channelName: 'Basic notifications',
          channelDescription: 'Notification channel for basic tests',
          defaultColor: Color(0xFF9D50DD),
          ledColor: Colors.white
      ),
      NotificationChannel(
          channelKey: 'badge_channel',
          channelName: 'Badge indicator notifications',
          channelDescription: 'Notification channel to activate badge indicator',
          channelShowBadge: true,
          defaultColor: Color(0xFF9D50DD),
          ledColor: Colors.yellow
      ),
      NotificationChannel(
          icon: 'resource://drawable/schedule_icon',
          channelKey: 'schedule',
          channelName: 'Scheduled Notifications',
          channelDescription: 'Notifications with schedule time',
          defaultColor: Color(0xFF9D50DD),
          ledColor: Colors.white
      ),
      NotificationChannel(
          channelKey: 'updated_channel',
          channelName: 'Channel to update',
          channelDescription: 'Notifications with not updated channel',
          defaultColor: Color(0xFF9D50DD),
          ledColor: Colors.white
      ),
      NotificationChannel(
          channelKey: 'low_intensity',
          channelName: 'Low intensity notifications',
          channelDescription: 'Notification channel for notifications with low intensity',
          defaultColor: Colors.green,
          ledColor: Colors.green,
          vibrationPattern: lowVibrationPattern
      ),
      NotificationChannel(
          channelKey: 'medium_intensity',
          channelName: 'Medium intensity notifications',
          channelDescription: 'Notification channel for notifications with medium intensity',
          defaultColor: Colors.yellow,
          ledColor: Colors.yellow,
          vibrationPattern: mediumVibrationPattern
      ),
      NotificationChannel(
          channelKey: 'high_intensity',
          channelName: 'High intensity notifications',
          channelDescription: 'Notification channel for notifications with high intensity',
          defaultColor: Colors.red,
          ledColor: Colors.red,
          vibrationPattern: highVibrationPattern
      ),
      NotificationChannel(
          icon: 'resource://drawable/res_power_ranger_thunder',
          channelKey: "custom_sound",
          channelName: "Custom sound notifications",
          channelDescription: "Notifications with custom sound",
          playSound: true,
          soundSource: 'resource://raw/res_morph_power_rangers',
          defaultColor: Colors.red,
          ledColor: Colors.red,
          vibrationPattern: lowVibrationPattern
      ),
      NotificationChannel(
          channelKey: "silenced",
          channelName: "Silenced notifications",
          channelDescription: "The most quiet notifications",
          playSound: false,
          enableVibration: false,
          enableLights: false
      ),
      NotificationChannel(
        icon: 'resource://drawable/res_media_icon',
        channelKey: 'media_player',
        channelName: 'Media player controller',
        channelDescription: 'Media player controller',
        defaultPrivacy: NotificationPrivacy.Public,
        enableVibration: false,
        enableLights: false,
        playSound: false,
        locked: true,
      ),
      NotificationChannel(
          channelKey: 'big_picture',
          channelName: 'Big pictures',
          channelDescription: 'Notifications with big and beautiful images',
          defaultColor: Color(0xFF9D50DD),
          ledColor: Color(0xFF9D50DD),
          vibrationPattern: lowVibrationPattern
      ),
      NotificationChannel(
          channelKey: 'big_text',
          channelName: 'Big text notifications',
          channelDescription: 'Notifications with a expandable body text',
          defaultColor: Colors.blueGrey,
          ledColor: Colors.blueGrey,
          vibrationPattern: lowVibrationPattern
      ),
      NotificationChannel(
          channelKey: 'inbox',
          channelName: 'Inbox notifications',
          channelDescription: 'Notifications with inbox layout',
          defaultColor: Color(0xFF9D50DD),
          ledColor: Color(0xFF9D50DD),
          vibrationPattern: mediumVibrationPattern
      ),
      NotificationChannel(
          channelKey: 'scheduled',
          channelName: 'Scheduled notifications',
          channelDescription: 'Notifications with schedule functionality',
          defaultColor: Color(0xFF9D50DD),
          ledColor: Color(0xFF9D50DD),
          vibrationPattern: lowVibrationPattern,
          importance: NotificationImportance.High,
      ),
      NotificationChannel(
          icon: 'resource://drawable/res_download_icon',
          channelKey: 'progress_bar',
          channelName: 'Progress bar notifications',
          channelDescription: 'Notifications with a progress bar layout',
          defaultColor: Colors.deepPurple,
          ledColor: Colors.deepPurple,
          vibrationPattern: lowVibrationPattern,
          onlyAlertOnce: true
      ),
      NotificationChannel(
          channelKey: 'grouped',
          channelName: 'Grouped notifications',
          channelDescription: 'Notifications with group functionality',
          groupKey: 'grouped',
          setAsGroupSummary: true,
          defaultColor: Colors.lightGreen,
          ledColor: Colors.lightGreen,
          vibrationPattern: lowVibrationPattern,
          importance: NotificationImportance.High
      )
    ]
  );

  runApp(App());
}

class App extends StatefulWidget {

  static final GlobalKey<NavigatorState> navKey = GlobalKey<NavigatorState>();

  static String name = 'Push Notifications - Example App';
  static Color mainColor = Color(0xFF9D50DD);

  @override
  _AppState createState() => _AppState();
}

class _AppState extends State<App> {

  @override
  void initState() {

    MediaPlayerCentral.addAll([
      MediaModel(diskImagePath: 'asset://assets/images/rock-disc.jpg',    colorCaptureSize: Size(788,800), bandName: 'Bright Sharp',   trackName: 'Champagne Supernova', trackSize: Duration(minutes: 4, seconds: 21)),
      MediaModel(diskImagePath: 'asset://assets/images/classic-disc.jpg', colorCaptureSize: Size(500,500), bandName: 'Best of Mozart', trackName: 'Allegro', trackSize: Duration(minutes: 7, seconds: 41)),
      MediaModel(diskImagePath: 'asset://assets/images/remix-disc.jpg',   colorCaptureSize: Size(500,500), bandName: 'Dj Allucard',    trackName: '21st Century', trackSize: Duration(minutes: 4, seconds: 59)),
      MediaModel(diskImagePath: 'asset://assets/images/dj-disc.jpg',      colorCaptureSize: Size(500,500), bandName: 'Dj Brainiak',    trackName: 'Speed of light', trackSize: Duration(minutes: 4, seconds: 59)),
      MediaModel(diskImagePath: 'asset://assets/images/80s-disc.jpg',     colorCaptureSize: Size(500,500), bandName: 'Back to the 80\'s',    trackName: 'Disco revenge', trackSize: Duration(minutes: 4, seconds: 59)),
      MediaModel(diskImagePath: 'asset://assets/images/old-disc.jpg',     colorCaptureSize: Size(500,500), bandName: 'PeacefulMind',  trackName: 'Never look at back', trackSize: Duration(minutes: 4, seconds: 59)),
    ]);

    super.initState();
  }

  @override
  Widget build(BuildContext context) {

    return MaterialApp(
        navigatorKey: App.navKey,
        title: App.name,
        color: App.mainColor,
        initialRoute: PAGE_HOME,
        //onGenerateRoute: generateRoute,
        routes: materialRoutes,
        builder: (context, child) =>
            MediaQuery(data: MediaQuery.of(context).copyWith(alwaysUse24HourFormat: true), child: child),
        theme: ThemeData(

          brightness: Brightness.light,

          primaryColor:   App.mainColor,
          accentColor:    Colors.blueGrey,
          primarySwatch:  Colors.blueGrey,
          canvasColor:    Colors.white,
          focusColor:     Colors.blueAccent,
          disabledColor:  Colors.grey,

          backgroundColor: Colors.blueGrey.shade400,

          appBarTheme: AppBarTheme(
              brightness: Brightness.dark,
              color: Colors.white,
              elevation: 0,
              iconTheme: IconThemeData(
                color: App.mainColor,
              ),
              textTheme: TextTheme(
                headline6: TextStyle(color: App.mainColor, fontSize: 18),
              )
          ),

          fontFamily: 'Robot',

          // Define the default TextTheme. Use this to specify the default
          // text styling for headlines, titles, bodies of text, and more.
          textTheme: TextTheme(
              headline1: TextStyle(fontSize: 64.0, height: 1.5, fontWeight: FontWeight.w500),
              headline2: TextStyle(fontSize: 52.0, height: 1.5, fontWeight: FontWeight.w500),
              headline3: TextStyle(fontSize: 48.0, height: 1.5, fontWeight: FontWeight.w500),
              headline4: TextStyle(fontSize: 32.0, height: 1.5, fontWeight: FontWeight.w500),
              headline5: TextStyle(fontSize: 28.0, height: 1.5, fontWeight: FontWeight.w500),
              headline6: TextStyle(fontSize: 22.0, height: 1.5, fontWeight: FontWeight.w500),
              subtitle1: TextStyle(fontSize: 18.0, height: 1.5, color: Colors.black54),
              subtitle2: TextStyle(fontSize: 12.0, height: 1.5, color: Colors.black54),
              button:    TextStyle(fontSize: 16.0, height: 1.5, color: Colors.black54),
              bodyText1: TextStyle(fontSize: 16.0, height: 1.5),
              bodyText2: TextStyle(fontSize: 16.0, height: 1.5),
          ),

          buttonTheme: ButtonThemeData(
            buttonColor: Colors.grey.shade200,
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.all(Radius.circular(5))
            ),
            padding: EdgeInsets.symmetric(vertical: 10.0, horizontal: 15.0),
            textTheme: ButtonTextTheme.accent,
          ),
        ),
    );
  }
}



