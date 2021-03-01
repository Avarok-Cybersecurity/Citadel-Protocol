import 'dart:io';

import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/socket_addr.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/utils.dart';

import '../u64.dart';

class GetSessionsResponse extends DomainSpecificResponse {
  final List<u64> cids;
  final List<String> usernames;
  final List<SocketAddr> endpoints;
  final List<bool> is_personals;
  final List<int> runtime_secs;

  GetSessionsResponse._(this.cids, this.usernames, this.endpoints, this.is_personals, this.runtime_secs);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.empty();
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.GetActiveSessions;
  }

  @override
  bool isFcm() {
    return false;
  }

  // String DSRlistSessions = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"GetActiveSessions\",\"usernames\":[\"nologik.test4\", \"nologik.test5\"],\"cids\":[\"2865279926\", \"123456789\"],\"endpoints\":[\"51.81.35.200:25000\", \"51.81.35.201:25001\"],\"is_personals\":[true, false],\"runtime_sec\":[\"8\", \"1000\"]}}";
  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      List<u64> cids = typeCastMap(infoNode["cids"], transform: u64.tryFrom);
      List<String> usernames = typeCastMap(infoNode["usernames"]);
      List<SocketAddr> endpoints= typeCastMap(infoNode["endpoints"], transform: SocketAddr.tryFrom);
      List<bool> is_personals = typeCastMap(infoNode["is_personals"]);
      List<int> runtime_secs = typeCastMap(infoNode["runtime_sec"], transform: tryParseInt);
      print("cids: " + cids.toString() + "\nusernames: " + usernames.toString() + "\nendpoints: " + endpoints.toString() + "\nis_personals: " + is_personals.toString() + "\nruntime_secs: " + runtime_secs.toString());
      if (!sameLengths([cids, usernames, endpoints, is_personals, runtime_secs])) {
        return Optional.empty();
      }

      return Optional.of(GetSessionsResponse._(cids, usernames, endpoints, is_personals, runtime_secs));
    } catch(_) {
      return Optional.empty();
    }
  }
}