import 'package:optional/optional.dart';

import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../standard_ticket.dart';

class TicketKernelResponse extends KernelResponse {
  final StandardTicket ticket;

  TicketKernelResponse(this.ticket);

  static Optional<TicketKernelResponse> tryFrom(String input) {
    var ticket = StandardTicket.tryFrom(input);
    if (ticket.isPresent) {
      return Optional.of(TicketKernelResponse(ticket.value));
    } else {
      return Optional.empty();
    }
  }

  @override
  Optional<DomainSpecificResponse> getDSR() {
    return Optional.empty();
  }

  @override
  Optional<String> getMessage() {
    return Optional.empty();
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.ResponseTicket;
  }

}