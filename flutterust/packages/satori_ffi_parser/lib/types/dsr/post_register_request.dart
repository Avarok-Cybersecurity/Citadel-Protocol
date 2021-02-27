
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

import '../u64.dart';

class PostRegisterRequest extends DomainSpecificResponse {
  final u64 mid;
  final String username;
  final u64 peerCid;
  final u64 implicatedCid;
  final Optional<Ticket> ticket;

  PostRegisterRequest._(this.mid, this.username, this.implicatedCid, this.peerCid, this.ticket);

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
    return DomainSpecificResponseType.PostRegisterRequest;
  }

  /// If no ticket is specified, then the invitation is implied to be of FCM type
  bool isFcm() {
    return this.ticket.isEmpty && this.mid == 0;
  }

  /*
    pub struct PostRegisterRequest {
      #[serde(with = "string")]
      pub mail_id: usize,
      #[serde(with = "base64_string")]
      pub username: Vec<u8>,
      #[serde(with = "string")]
      pub implicated_cid: u64,
      #[serde(with = "string")]
      pub peer_cid: u64,
      #[serde(with = "string")]
      pub ticket: u64
    }
   */

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode, MessageParseMode base64MapMode) {
    try {
      u64 mid = u64.tryFrom(infoNode["mail_id"]).value;
      String username = mapBase64(infoNode["username"], base64MapMode);
      u64 peerCid = u64.tryFrom(infoNode["peer_cid"]).value;
      u64 implicatedCid = u64.tryFrom(infoNode["implicated_cid"]).value;

      Optional<Ticket> ticket = Ticket.tryFrom(infoNode["ticket"]);
      return Optional.of(PostRegisterRequest._(mid, username, implicatedCid, peerCid, ticket));
    } on Exception catch(_) {
      return Optional.empty();
    }
  }

}