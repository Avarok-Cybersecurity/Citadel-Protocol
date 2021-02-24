import 'package:optional/optional.dart';

import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../ticket.dart';

class DomainSpecificKernelResponse<T extends DomainSpecificResponse> extends KernelResponse {
  T dsr;

  DomainSpecificKernelResponse(T dsr) {
    this.dsr = dsr;
  }

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