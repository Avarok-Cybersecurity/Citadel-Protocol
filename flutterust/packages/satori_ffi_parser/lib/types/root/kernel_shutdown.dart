
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

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
  Optional<Ticket> getTicket() {
    return Optional.empty();
  }

  @override
  KernelResponseType getType() {
    return KernelResponseType.KernelShutdown;
  }

  static Optional<KernelResponse> tryFrom(List<dynamic> infoNode, MessageParseMode mapBase64Strings) {
    if (infoNode.length != 1) {
      return Optional.empty();
    } else {
      String message = mapBase64(infoNode[0], mapBase64Strings);
      return Optional.of(KernelShutdown(message));
    }
  }

}