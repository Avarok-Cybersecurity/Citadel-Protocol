import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/screens/register.dart';
import 'package:satori_ffi_parser/types/dsr/register_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';

class RegisterHandler implements AbstractHandler {
  final RegisterIsolateTransfer info;

  RegisterHandler(this.info);
//224533
  @override
  void onConfirmation(KernelResponse kernelResponse) async {
    if (kernelResponse.getTicket().isPresent) {
      print("Showing loader");
      //await EasyLoading.show();
    }
  }

  @override
  void onErrorReceived(KernelResponse kernelResponse) {
    print("[Register Handler] Registration failed: " + kernelResponse.getMessage().value);
    this.info.sendPort.send(RegisterUISignal(RegisterUpdateSignalType.RegisterFailure, message: kernelResponse.getMessage().orElse("Unable to register (unknown)")));
  }

  @override
  void onTicketReceived(KernelResponse kernelResponse) {
    RegisterResponse resp = kernelResponse.getDSR().value;
    if (resp.success) {
      print("[Register Handler] SUCCESS!");
      this.info.sendPort.send(RegisterUISignal(RegisterUpdateSignalType.RegisterSuccess, message: kernelResponse.getMessage().orElse("Successfully registered!")));
    } else {
      this.onErrorReceived(kernelResponse);
    }
  }

}