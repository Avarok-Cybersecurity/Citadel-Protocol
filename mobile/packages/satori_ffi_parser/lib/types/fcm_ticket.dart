/*
  pub struct FcmTicket {
    #[serde(with = "string")]
    source_cid: u64,
    #[serde(with = "string")]
    target_cid: u64,
    #[serde(with = "string")]
    ticket: u64
}
*/

import 'package:optional/optional.dart';
import 'package:quiver/core.dart' show hash3;
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class FcmTicket extends Ticket {
  final u64 sourceCid;
  final u64 targetCid;
  final u64 ticket;

  FcmTicket(this.sourceCid, this.targetCid, this.ticket);

  static Optional<FcmTicket> tryFromMap(Map<String, dynamic> map) {
    try {
      u64 sourceCid = u64.tryFrom(map["source_cid"]).value;
      u64 targetCid = u64.tryFrom(map["target_cid"]).value;
      u64 ticket = u64.tryFrom(map["ticket"]).value;
      return Optional.of(FcmTicket(sourceCid, targetCid, ticket));
    } catch(_) {
      return Optional.empty();
    }
  }

  bool operator == (o) => o is FcmTicket && o.sourceCid == sourceCid && o.targetCid == targetCid && o.ticket == ticket;

  @override
  String toString() {
    return "[Source: " + this.sourceCid.toString() + " | Target: " + this.targetCid.toString() + " | Raw Ticket: " + this.ticket.toString() + " ]";
  }

  @override
  bool eq(Ticket other) {
    return other == this;
  }

  @override
  u64 get id => this.ticket;

  @override
  int get hashCode => hash3(this.ticket, this.sourceCid, this.targetCid);
}