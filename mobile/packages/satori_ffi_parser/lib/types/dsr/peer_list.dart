import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/utils.dart';

import '../u64.dart';

class PeerListResponse extends DomainSpecificResponse {
  final List<u64> cids;
  final List<bool> isOnlines;
  final StandardTicket ticket;

  PeerListResponse._(this.cids, this.isOnlines, this.ticket);

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
    return DomainSpecificResponseType.PeerList;
  }

  @override
  bool isFcm() {
    return false;
  }

  /*
    pub struct PeerList {
    #[serde(serialize_with = "string_vec")]
    cids: Vec<u64>,
    is_onlines: Vec<bool>,
    #[serde(serialize_with = "string")]
    ticket: u64
}
   */
  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    List<u64> cids = typeCastMap(infoNode["cids"], transform: u64.tryFrom);
    List<bool> isOnlines = typeCastMap(infoNode["is_onlines"]);
    print("cids: " + cids.toString() + "\nis_onlines: "+ isOnlines.toString());
    if (!sameLengths([cids, isOnlines])) {
      return Optional.empty();
    }

    return StandardTicket.tryFrom(infoNode["ticket"]).map((ticket) => PeerListResponse._(cids, isOnlines, ticket));
  }
}