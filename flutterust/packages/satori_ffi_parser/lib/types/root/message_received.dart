
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class MessageReceived extends KernelResponse {
  final Ticket ticket;

  MessageReceived(this.ticket);

  @override
  Optional<DomainSpecificResponse> getDSR() => Optional.empty();

  @override
  Optional<String> getMessage() => Optional.empty();

  @override
  Optional<Ticket> getTicket() => Optional.of(this.ticket);

  @override
  KernelResponseType getType() => KernelResponseType.MessageReceived;

}