import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

import '../fcm_ticket.dart';
import '../u64.dart';

class PostRegisterRequest extends DomainSpecificResponse {
  final u64 mid;
  final String username;
  final u64 peerCid;
  final u64 implicatedCid;
  final Ticket ticket;
  final bool isFcmType;

  PostRegisterRequest._(this.mid, this.username, this.implicatedCid, this.peerCid, this.ticket, this.isFcmType);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<Ticket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.PostRegisterRequest;
  }


  @override
  bool isFcm() {
    return this.isFcmType;
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
      u64 rawTicket = u64.tryFrom(infoNode["ticket"]).value;
      bool isFcm = infoNode["fcm"];
      
      var ticket = isFcm ? FcmTicket(peerCid, implicatedCid, rawTicket) : StandardTicket(rawTicket);
      
      return Optional.of(PostRegisterRequest._(mid, username, implicatedCid, peerCid, ticket, isFcm));
    } catch(_) {
      return Optional.empty();
    }
  }

}