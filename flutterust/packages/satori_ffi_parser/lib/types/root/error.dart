import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/parser.dart';

import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../ticket.dart';

class ErrorKernelResponse extends KernelResponse {
  Optional<Ticket> ticket;
  String message;

  ErrorKernelResponse(Optional<Ticket> ticket, String message) {
    this.ticket = ticket;
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
     return this.ticket;
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.Error;
  }

  // String ErrorTypeExample = "{\"type\":\"Error\",\"info\":[\"10\",\"User nologik.test is already an active session ...\"]}";
  static Optional<KernelResponse> tryFrom(List<dynamic> infoNode, MessageParseMode mapBase64Strings) {
    if (infoNode.length != 2) {
      return Optional.empty();
    } else {
      String id = infoNode[0];
      String message = mapBase64(infoNode[1], mapBase64Strings);
      return Optional.of(ErrorKernelResponse(Ticket.tryFrom(id), message));
    }
  }
}