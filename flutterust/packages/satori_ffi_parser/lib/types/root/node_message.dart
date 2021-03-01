import 'package:optional/optional.dart';

import '../../parser.dart';
import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../standard_ticket.dart';
import '../u64.dart';
import '../virtual_connection_type.dart';

class NodeMessageKernelResponse extends KernelResponse {
  StandardTicket ticket;
  u64 cid;
  u64 icid;
  u64 peerCid;
  String message;

  NodeMessageKernelResponse(StandardTicket ticket, u64 cid, u64 icid, u64 peerCid, String message) {
    this.ticket = ticket;
    this.cid = cid;
    this.icid = icid;
    this.peerCid = peerCid;
    this.message = message;
  }

  @override
  Optional<DomainSpecificResponse> getDSR() {
    return Optional.empty();
  }

  @override
  Optional<String> getMessage() {
    return Optional.of(this.message);
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.ofNullable(this.ticket);
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.NodeMessage;
  }

  VirtualConnectionType getVirtualConnectionType() {
    if (this.icid != u64.zero) {
      if (this.peerCid != u64.zero) {
        // nonzero icid && nonzero peer cid => HyperLAN Peer -> HyperWAN Peer
        return VirtualConnectionType.HyperLANPeerToHyperWANPeer;
      } else {
        // nonzero icid && zero peer cid => client -> hyperWAN server
        return VirtualConnectionType.HyperLANPeerToHyperWANServer;
      }
    } else {
      if (this.peerCid != u64.zero) {
        // zero icid && nonzero peer-cid => hyperlan p2p
        return VirtualConnectionType.HyperLANPeerToHyperLANPeer;
      } else {
        // zero icid && zero peer-cid => server to client message
        return VirtualConnectionType.HyperLANPeerToHyperLANServer;
      }
    }
  }

  static Optional<KernelResponse> tryFrom(List<dynamic> infoNode, MessageParseMode mapBase64Strings) {
    if (infoNode.length != 5) {
      return Optional.empty();
    } else {
      var ticket = StandardTicket.tryFrom(infoNode[0]);
      var cid = u64.tryFrom(infoNode[1]);
      var icid = u64.tryFrom(infoNode[2]);
      var peerCid = u64.tryFrom(infoNode[3]);
      String message = mapBase64(infoNode[4], mapBase64Strings);

      if (ticket.isEmpty || cid.isEmpty || icid.isEmpty || peerCid.isEmpty) {
        return Optional.empty();
      }

      return Optional.of(NodeMessageKernelResponse(ticket.value, cid.value, icid.value, peerCid.value, message));
    }
  }
}