
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/fcm_ticket.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class FcmTicketResponse extends KernelResponse {
  final FcmTicket ticket;

  FcmTicketResponse(this.ticket);

  @override
  Optional<DomainSpecificResponse> getDSR() {
    return Optional.empty();
  }

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<Ticket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.ResponseFcmTicket;
  }

  static Optional<FcmTicketResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      return FcmTicket.tryFromMap(infoNode).map((ticket) => FcmTicketResponse(ticket));
    } catch(_) {
      return Optional.empty();
    }
  }

}