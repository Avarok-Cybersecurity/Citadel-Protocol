
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class PostRegisterResponse extends DomainSpecificResponse {
  final Ticket ticket;
  final bool accept;
  final String username;

  PostRegisterResponse._(this.ticket, this.accept, this.username);

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

  /*

    pub struct PostRegisterResponse {
      #[serde(with = "string")]
      ticket: u64,
      accept: bool,
      #[serde(with = "base64_string")]
      username: Vec<u8>
    }

   */


  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode, MessageParseMode base64MapMode) {
    try {
      bool accept = infoNode["accept"];
      String username = mapBase64(infoNode["username"], base64MapMode);

      return Ticket.tryFrom(infoNode["ticket"]).map((ticket) => PostRegisterResponse._(ticket, accept, username));
    } on Exception catch(_) {
      return Optional.empty();
    }
  }
}