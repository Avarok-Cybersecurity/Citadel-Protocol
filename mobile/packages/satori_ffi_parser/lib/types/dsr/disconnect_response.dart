import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/types/virtual_connection_type.dart';

import '../domain_specific_response.dart';
import '../u64.dart';

class DisconnectResponse extends DomainSpecificResponse {
  final u64 implicatedCid;
  final u64 icid;
  final u64 peerCid;
  final Optional<StandardTicket> ticket;
  final VirtualConnectionType virtualConnectionType;

  DisconnectResponse._(this.virtualConnectionType, this.implicatedCid, this.icid, this.peerCid, this.ticket);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<StandardTicket> getTicket() {
    return this.ticket;
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.Disconnect;
  }

  @override
  bool isFcm() {
    return false;
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

      Optional<StandardTicket> ticket = StandardTicket.tryFrom(leaf[0]);
      return u64.tryFrom(leaf[1]).flatMap((implicatedCid) {
        Optional<u64> peerCid;
        u64 icid = u64.zero;
        if (vConnType == VirtualConnectionType.HyperLANPeerToHyperLANPeer) {
          if (leaf.length != 3) {
            return Optional.empty();
          }

          peerCid = u64.tryFrom(leaf[2]);
        } else {
          peerCid = Optional.of(u64.zero);
        }

        return peerCid.flatMap((peerCid) {
          return Optional.of(DisconnectResponse._(
              vConnType, implicatedCid, icid, peerCid, ticket));
        });
      });
    });
  }
}
