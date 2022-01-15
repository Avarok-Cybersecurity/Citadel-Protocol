
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/fcm_ticket.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class PostRegisterResponse extends DomainSpecificResponse {

  final u64 implicatedCid;
  final u64 peerCid;
  final bool isFCM;
  final Ticket ticket;
  final bool accept;
  final String username;

  PostRegisterResponse._(this.implicatedCid, this.peerCid, this.isFCM, this.ticket, this.accept, this.username);

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
    return DomainSpecificResponseType.PostRegisterResponse;
  }

  @override
  bool isFcm() {
    return this.isFCM;
  }

  /*

    pub struct PostRegisterResponse {
    #[serde(with = "string")]
    implicated_cid: u64,
    #[serde(with = "string")]
    peer_cid: u64,
    #[serde(with = "string")]
    ticket: u64,
    accept: bool,
    #[serde(with = "base64_string")]
    username: Vec<u8>,
    fcm: bool
}

   */


  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode, MessageParseMode base64MapMode) {
    try {
      u64 implicatedCid = u64.tryFrom(infoNode["implicated_cid"]).value;
      u64 peerCid = u64.tryFrom(infoNode["peer_cid"]).value;
      u64 ticketRaw = u64.tryFrom(infoNode["ticket"]).value;

      bool accept = infoNode["accept"];
      String username = mapBase64(infoNode["username"], base64MapMode);
      bool isFcm = infoNode["fcm"];

      var ticket = isFcm ? FcmTicket(implicatedCid, peerCid, ticketRaw) : StandardTicket(ticketRaw);

      return Optional.of(PostRegisterResponse._(implicatedCid, peerCid, isFcm, ticket, accept, username));
    } catch(_) {
      return Optional.empty();
    }
  }
}