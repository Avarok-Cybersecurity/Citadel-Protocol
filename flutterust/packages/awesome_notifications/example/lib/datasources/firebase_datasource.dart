import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' show Response;

import 'common/http_datasource.dart';

class FirebaseDataSource extends HttpDataSource {

  /// ************************************************************************************
  ///
  /// SINGLETON CONSTRUCTOR PATTERN
  ///
  /// ************************************************************************************
  ///
  static FirebaseDataSource _instance;
  factory FirebaseDataSource({
    String serverSecret
  }) {
    _instance ??= FirebaseDataSource._internalConstructor();
    return _instance;
  }

  FirebaseDataSource._internalConstructor()
      : super(
        'fcm.googleapis.com',
        isUsingHttps: true,
        isCertificateHttps: false
      );

  /// ************************************************************************************
  ///
  /// FETCH DATA METHODS
  ///
  /// ************************************************************************************

  Future<String> _pushNotification({String firebaseServerKey, Map<String, dynamic> body = const {}}) async {

    if((firebaseServerKey ?? '').isEmpty){
      return 'Server Key not defined';
    }

    Response response = await fetchData(
        directory: '/fcm/send',
        headers: {
          'Authorization': 'key=$firebaseServerKey',
          'Content-Type': 'application/json'
        },
        body: jsonEncode(body)
    );

    if(response.statusCode == 200){
      return response.bodyBytes.toString();
    }

    return '';
  }

  Future<String> pushBasicNotification({
    String firebaseServerKey,
    String firebaseAppToken,
    int notificationId,
    String title,
    String body,
    Map<String, String> payload = const {}
  }) async {

    return await _pushNotification(
        firebaseServerKey: firebaseServerKey,
        body: getFirebaseExampleContent(firebaseAppToken: firebaseAppToken)
    );
  }

  Map<String, dynamic> getFirebaseExampleContent({
    String firebaseAppToken
  }){
    return {
      'collapse_key': 'type_a',
      'to': firebaseAppToken,
      'data': {
        "content": {
          "id": 100,
          "channelKey": "big_picture",
          "title": "Huston!\nThe eagle has landed!",
          "body": "A small step for a man, but a giant leap to Flutter's community!",
          "notificationLayout": "BigPicture",
          "largeIcon": "https://avidabloga.files.wordpress.com/2012/08/emmemc3b3riadeneilarmstrong3.jpg",
          "bigPicture": "https://www.dw.com/image/49519617_303.jpg",
          "showWhen": true,
          "autoCancel": true,
          "privacy": "Private"
        }
      }
    };
  }
}