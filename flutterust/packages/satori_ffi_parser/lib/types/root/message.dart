import 'package:optional/optional.dart';

import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../ticket.dart';

class MessageKernelResponse extends KernelResponse {
  String message;

  MessageKernelResponse(String message) {
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
  Optional<Ticket> getTicket() {
    return Optional.empty();
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.Message;
  }

}