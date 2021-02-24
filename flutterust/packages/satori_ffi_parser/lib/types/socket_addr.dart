import 'dart:io';

import 'package:optional/optional.dart';

class SocketAddr {
  InternetAddress ip;
  int port;

  SocketAddr(InternetAddress ip, int port) {
    this.ip = ip;
    this.port = port;
  }

  static Optional<SocketAddr> tryFromUncheckedPort(InternetAddress ip, String port) {
    return parsePort(port)
        .map((port) => SocketAddr(ip, port));
  }

  static Optional<SocketAddr> tryFrom<T>(T input) {
    if (input is String) {
      List<String> items = input.split(":");
      if (items.length != 2) {
        return Optional.empty();
      }

      InternetAddress ip = InternetAddress.tryParse(items[0]);
      if (ip == null) {
        return Optional.empty();
      }

      return tryFromUncheckedPort(ip, items[1]);
    } else {
      return Optional.empty();
    }
  }

  bool is_v4() {
    return this.ip.type == InternetAddressType.IPv4;
  }

  bool is_v6() {
    return this.ip.type == InternetAddressType.IPv6;
  }

  bool operator == (o) => o is SocketAddr && o.ip.rawAddress == this.ip.rawAddress && o.port == this.port;

  @override
  String toString() {
    return this.ip.address + ":" + this.port.toString();
  }
}

Optional<int> parsePort(String prt) {
  int port = int.tryParse(prt);
  if (port == null) {
    return Optional.empty();
  }

  if (port < 0 || port > 65535) {
    return Optional.empty();
  }

  return Optional.of(port);
}