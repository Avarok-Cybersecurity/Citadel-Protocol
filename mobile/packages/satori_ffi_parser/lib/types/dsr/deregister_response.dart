
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class DeregisterResponse extends DomainSpecificResponse {
  final u64 implicatedCid;
  final u64 peerCid;
  final Optional<StandardTicket> ticket;
  final bool success;

  DeregisterResponse._(this.implicatedCid, this.peerCid, this.ticket, this.success);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<Ticket> getTicket() {
    return this.ticket;
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.DeregisterResponse;
  }

  @override
  bool isFcm() {
    return false;
  }

  static Optional<DeregisterResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      u64 implicatedCid = u64.tryFrom(infoNode["implicated_cid"]).value;
      u64 peerCid = u64.tryFrom(infoNode["peer_cid"]).value;
      Optional<StandardTicket> ticket = StandardTicket.tryFrom(infoNode["ticket"]);
      bool success = infoNode["success"];

      return Optional.of(DeregisterResponse._(implicatedCid, peerCid, ticket, success));
    } catch(_) {
      return Optional.empty();
    }
  }

}