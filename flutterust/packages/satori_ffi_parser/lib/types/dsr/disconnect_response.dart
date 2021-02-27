import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/virtual_connection_type.dart';

import '../domain_specific_response.dart';
import '../u64.dart';

class DisconnectResponse extends DomainSpecificResponse {
  final u64 implicated_cid;
  final u64 icid;
  final u64 peer_cid;
  final Optional<Ticket> ticket;
  final VirtualConnectionType virtualConnectionType;

  DisconnectResponse._(this.virtualConnectionType, this.implicated_cid, this.icid, this.peer_cid, this.ticket);

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
    return DomainSpecificResponseType.Disconnect;
  }

  /*
    HyperLANPeerToHyperLANServer(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64),
    HyperLANPeerToHyperLANPeer(#[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64, #[serde(serialize_with = "string")] u64)
  */
  static Optional<DomainSpecificResponse> tryFrom(
      Map<String, dynamic> infoNode) {
    return findFirstInKeys(infoNode).flatMap((vConnType) {
      print("VConn type: " + vConnType.toString());
      List<dynamic> leaf = infoNode[vConnType.toString().split(".").last];
      if (leaf.length < 2) {
        return Optional.empty();
      }

      Optional<Ticket> ticket = Ticket.tryFrom(leaf[0]);
      return u64.tryFrom(leaf[1]).flatMap((implicated_cid) {
        Optional<u64> peer_cid;
        u64 icid = u64.zero;
        if (vConnType == VirtualConnectionType.HyperLANPeerToHyperLANPeer) {
          if (leaf.length != 3) {
            return Optional.empty();
          }

          peer_cid = u64.tryFrom(leaf[2]);
        } else {
          peer_cid = Optional.of(u64.zero);
        }

        return peer_cid.flatMap((peer_cid) {
          return Optional.of(DisconnectResponse._(
              vConnType, implicated_cid, icid, peer_cid, ticket));
        });
      });
    });
  }
}
