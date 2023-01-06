import 'dart:convert';
import 'dart:io';

class GoogleSecureDnsClient {
  static Future<List<String>> getIpOf(String addr) async {
    var client = HttpClient();
    var request = await client.getUrl(Uri.parse('https://dns.google/resolve?name=$addr'));
    var response = await request.close();

    var rawMap = await response.transform(Utf8Decoder()).first;
    Map<String, dynamic> map = json.decode(rawMap);

    return (map['Answer'] as List<dynamic>).where((element) => element['data'] is String).map((e) => e['data'] as String).toList();
  }
}
