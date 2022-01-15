import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';

class DomainSpecificKernelResponse<T extends DomainSpecificResponse> extends KernelResponse {
  final T dsr;

  DomainSpecificKernelResponse(this.dsr);

  @override
  Optional<DomainSpecificResponse> getDSR() {
    return Optional.of(this.dsr);
  }

  @override
  Optional<String> getMessage() {
    return this.dsr.getMessage();
  }

  @override
  Optional<Ticket> getTicket() {
    return this.dsr.getTicket();
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.DomainSpecificResponse;
  }

}