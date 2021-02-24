import '../domain_specific_response.dart';
import '../kernel_response.dart';
import '../kernel_response_type.dart';
import '../ticket.dart';
import 'package:optional/optional.dart';

class ConfirmationKernelResponse extends KernelResponse {

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
    return Optional.empty();
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.Confirmation;
  }

}