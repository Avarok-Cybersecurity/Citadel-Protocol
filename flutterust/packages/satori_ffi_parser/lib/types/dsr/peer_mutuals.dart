import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/utils.dart';

import '../u64.dart';

class PeerMutualsResponse extends DomainSpecificResponse {
  final List<u64> cids;
  final List<String> usernames;
  final List<bool> isOnlines;
  final List<bool> fcmReachable;
  final u64 implicatedCid;
  final StandardTicket ticket;

  PeerMutualsResponse._(this.cids, this.usernames, this.isOnlines, this.fcmReachable, this.implicatedCid, this.ticket);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.PeerMutuals;
  }

  @override
  bool isFcm() {
    return false;
  }

  /*
    pub struct PeerMutuals {
      #[serde(serialize_with = "string_vec")]
      cids: Vec<u64>,
      usernames: Vec<String>,
      is_onlines: Vec<bool>,
      fcm_reachable: Vec<bool>,
      implicated_cid: u64,
      ticket: u64
    }
   */
  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      List<u64> cids = typeCastMap(infoNode["cids"], transform: u64.tryFrom);
      List<String> usernames = typeCastMap(infoNode["usernames"]);
      List<bool> isOnlines = typeCastMap(infoNode["is_onlines"]);
      List<bool> fcmReachables = typeCastMap(infoNode["fcm_reachable"]);
      u64 implicatedCid = u64.tryFrom(infoNode["implicated_cid"]).value;
      StandardTicket ticket = StandardTicket.tryFrom(infoNode["ticket"]).value;

      if (!sameLengths([cids, isOnlines, usernames, fcmReachables])) {
        return Optional.empty();
      }

      return Optional.of(PeerMutualsResponse._(cids, usernames, isOnlines, fcmReachables, implicatedCid, ticket));
    } catch(_) {
      return Optional.empty();
    }
  }
}