import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/fcm_ticket.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../standard_ticket.dart';

class ErrorKernelResponse extends KernelResponse {
  final Optional<Ticket> ticket;
  final String message;

  ErrorKernelResponse._(this.ticket, this.message);

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
  static Optional<KernelResponse> tryFromStd(List<dynamic> infoNode, MessageParseMode mapBase64Strings) {
    if (infoNode.length != 2) {
      return Optional.empty();
    } else {
      String id = infoNode[0];
      String message = mapBase64(infoNode[1], mapBase64Strings);
      return Optional.of(ErrorKernelResponse._(StandardTicket.tryFrom(id), message));
    }
  }

  static Optional<KernelResponse> tryFromFcm(List<dynamic> infoNode, MessageParseMode mapBase64Strings) {
    try {
      FcmTicket ticket = FcmTicket.tryFromMap(infoNode[0]).value;
      String message = mapBase64(infoNode[1], mapBase64Strings);
      return Optional.of(ErrorKernelResponse._(Optional.of(ticket), message));
    } catch(e) {
      return Optional.empty();
    }
  }
}