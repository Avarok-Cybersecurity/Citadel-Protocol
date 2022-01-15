import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';

import '../u64.dart';

class RtdbConfig {
  final String apiKey;
  final String url;

  RtdbConfig(this.apiKey, this.url);
}

class ConnectResponse extends DomainSpecificResponse {
  final String message;
  final StandardTicket ticket;
  final u64 implicatedCid;
  final bool success;
  final Optional<String> jwt;
  final Optional<RtdbConfig> rtdbConfig;

  Optional<String> username = Optional.empty();

  ConnectResponse._(this.success, this.ticket, this.implicatedCid, this.message, this.jwt, this.rtdbConfig);

  @override
  Optional<String> getMessage() {
    return Optional.of(this.message);
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.Connect;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    bool success = infoNode.containsKey("Success");
    List<dynamic> leaf = infoNode[success ? "Success" : "Failure"];
    if ((success && leaf.length != 5) || (!success && leaf.length != 3)) {
      return Optional.empty();
    }

    var ticket = StandardTicket.tryFrom(leaf[0]);
    var implicatedCid = u64.tryFrom(leaf[1]);
    String message = leaf[2];

    Optional<String> jwt = success ? Optional.of(leaf[3]) : Optional.empty();
    Optional<RtdbConfig> rtdb = success ? ConnectResponse.tryParseRtdbConfig(leaf) : Optional.empty();

    return ticket.isPresent && implicatedCid.isPresent ? Optional.of(ConnectResponse._(success, ticket.value, implicatedCid.value, message, jwt, rtdb)) : Optional.empty();
  }

  static Optional<RtdbConfig> tryParseRtdbConfig(List<dynamic> leaf) {
    try {
      Map<String, dynamic> json = leaf[4];
      String apiKey = json["api_key"];
      String url = json["url"];

      return Optional.of(RtdbConfig(apiKey, url));
    } catch (_) {
      return Optional.empty();
    }
  }

  void attachUsername(String username) {
    this.username = Optional.of(username);
  }

  Optional<String> getAttachedUsername() {
    return this.username;
  }

  @override
  bool isFcm() {
    return false;
  }
}