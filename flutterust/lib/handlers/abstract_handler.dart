import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

abstract class AbstractHandler {
  void onConfirmation(KernelResponse kernelResponse);
  CallbackStatus onTicketReceived(KernelResponse kernelResponse);
  void onErrorReceived(ErrorKernelResponse kernelResponse);

  static bool validTypes(KernelResponse kernelResponse, DomainSpecificResponseType dsrType) {
    return kernelResponse.getDSR().map((val) => val.getType()) == Optional.of(dsrType);
  }
}