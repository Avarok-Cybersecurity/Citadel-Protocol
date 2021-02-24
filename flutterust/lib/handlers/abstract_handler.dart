import 'package:satori_ffi_parser/types/kernel_response.dart';

abstract class AbstractHandler {
  void onConfirmation(KernelResponse kernelResponse);
  void onTicketReceived(KernelResponse kernelResponse);
  void onErrorReceived(KernelResponse kernelResponse);
}