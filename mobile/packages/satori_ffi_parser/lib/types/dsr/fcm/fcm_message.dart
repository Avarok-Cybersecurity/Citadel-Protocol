
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/fcm_ticket.dart';

class FcmMessage extends DomainSpecificResponse {
  final String message;
  final FcmTicket ticket;

  FcmMessage._(this.message, this.ticket);

  @override
  Optional<String> getMessage() {
    return Optional.of(this.message);
  }

  @override
  Optional<FcmTicket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.FcmMessage;
  }

  @override
  bool isFcm() {
    return true;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode, MessageParseMode base64ParseMode) {
    try {
      String message = mapBase64(infoNode["message"], base64ParseMode);
      Map<String, dynamic> ticketNode = infoNode["fcm_ticket"];

      return FcmTicket.tryFromMap(ticketNode).map((ticket) => FcmMessage._(message, ticket));
    } catch(_) {
      return Optional.empty();
    }
  }

}