// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility that Flutter provides. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/types/socket_addr.dart';

void main() {
  testWidgets('Counter increments smoke test', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    //await tester.pumpWidget(MyApp());

    // Verify that our counter starts at 0.
    expect(find.text('0'), findsOneWidget);
    expect(find.text('1'), findsNothing);

    // Tap the '+' icon and trigger a frame.
    await tester.tap(find.byIcon(Icons.add));
    await tester.pump();

    // Verify that our counter has incremented.
    expect(find.text('0'), findsNothing);
    expect(find.text('1'), findsOneWidget);
  });

  test('socket parse', () async {
    HttpOverrides.global = null;
    String first = "192.168.2.1";
    String second = "192.168.2.1:33333";
    String third = "thomaspbraun.com";
    String fourth = "thomaspbraun.com:33333";
    SocketAddr addrFirst = (await Utils.resolveAddr(first)).value;
    print("Resolved: " + addrFirst.toString());
    expect(InternetAddress.tryParse("192.168.2.1"), addrFirst.ip);
    expect(25021, addrFirst.port);

    SocketAddr addrSecond = (await Utils.resolveAddr(second)).value;
    print("Resolved: " + addrSecond.toString());
    expect(InternetAddress.tryParse("192.168.2.1"), addrSecond.ip);
    expect(33333, addrSecond.port);

    SocketAddr addrThird = (await Utils.resolveAddr(third)).value;
    print("Resolved: " + addrThird.toString());
    //expect(first, addrFirst.ip);
    expect(25021, addrThird.port);

    SocketAddr addrFourth = (await Utils.resolveAddr(fourth)).value;
    print("Resolved: " + addrFourth.toString());
    //expect(first, addrFirst.ip);
    expect(33333, addrFourth.port);

    String bad = "123:123:123";
    assert((await Utils.resolveAddr(bad)).isEmpty);
  });
}
