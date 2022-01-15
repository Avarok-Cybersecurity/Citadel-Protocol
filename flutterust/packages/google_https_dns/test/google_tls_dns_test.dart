import 'package:google_https_dns/library.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {

    test('First Test', () async {
      var res = await GoogleSecureDnsClient.getIpOf('thomaspbraun.com');
      print('IP Addr: $res');
    });
  });
}
