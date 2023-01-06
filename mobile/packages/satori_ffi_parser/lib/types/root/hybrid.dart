import 'package:optional/optional.dart';

import '../../parser.dart';
import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../standard_ticket.dart';

class HybridKernelResponse extends KernelResponse {
  final StandardTicket ticket;
  final String message;

  HybridKernelResponse(this.ticket, this.message);

  @override
  Optional<DomainSpecificResponse> getDSR() {
    return Optional.empty();
  }

  @override
  Optional<String> getMessage() {
    return Optional.of(this.message);
  }

  @override
  Optional<StandardTicket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.ResponseHybrid;
  }

  static Optional<KernelResponse> tryFrom(List<dynamic> infoNode, MessageParseMode mapBase64Strings) {
    if (infoNode.length != 2) {
      return Optional.empty();
    } else {
      var id = StandardTicket.tryFrom(infoNode[0]);
      String message = mapBase64(infoNode[1], mapBase64Strings);
      return id.map((ticket) => HybridKernelResponse(ticket, message));
    }
  }

}