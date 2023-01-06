import 'dart:io';

import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/main.dart';

class SocketAddr {
  final InternetAddress ip;
  final int port;

  SocketAddr(this.ip, this.port);

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

      InternetAddress? ip = InternetAddress.tryParse(items[0]);
      if (ip == null) {
        return Optional.empty();
      }

      return tryFromUncheckedPort(ip, items[1]);
    } else {
      return Optional.empty();
    }
  }

  bool isV4() {
    return this.ip.type == InternetAddressType.IPv4;
  }

  bool isV6() {
    return this.ip.type == InternetAddressType.IPv6;
  }

  bool operator == (o) => o is SocketAddr && o.ip.address == this.ip.address && o.port == this.port;

  @override
  String toString() {
    return this.ip.address + ":" + this.port.toString();
  }

  @override
  int get hashCode => hashcode2(this.ip.address.hashCode, this.port.hashCode);

}

Optional<int> parsePort(String prt) {
  int? port = int.tryParse(prt);
  if (port == null) {
    return Optional.empty();
  }

  if (port < 0 || port > 65535) {
    return Optional.empty();
  }

  return Optional.of(port);
}