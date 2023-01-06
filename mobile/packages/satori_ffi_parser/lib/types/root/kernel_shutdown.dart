
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/standard_ticket.dart';

import '../../parser.dart';

class KernelShutdown extends KernelResponse {
  final String message;

  KernelShutdown(this.message);

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
    return Optional.empty();
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.KernelShutdown;
  }

  static Optional<KernelResponse> tryFrom(String infoNode, MessageParseMode mapBase64Strings) {
    String message = mapBase64(infoNode, mapBase64Strings);
    return Optional.of(KernelShutdown(message));
  }

}