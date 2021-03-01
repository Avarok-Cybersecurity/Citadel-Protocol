import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/fcm_ticket.dart';

class FcmMessageReceived extends DomainSpecificResponse {
  final FcmTicket ticket;

  FcmMessageReceived._(this.ticket);

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<FcmTicket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.FcmMessageReceived;
  }

  @override
  bool isFcm() {
    return true;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      Map<String, dynamic> ticketNode = infoNode["fcm_ticket"];
      return FcmTicket.tryFromMap(ticketNode).map((ticket) => FcmMessageReceived._(ticket));
    } catch(_) {
      return Optional.empty();
    }
  }

}