import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/screens/register.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/register_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

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
  void onErrorReceived(ErrorKernelResponse kernelResponse) async {
    await EasyLoading.dismiss();
    print("[Register Handler] Registration failed: " + kernelResponse.message);
    this.info.sendPort.send(RegisterUISignal(RegisterUpdateSignalType.RegisterFailure, message: kernelResponse.getMessage().orElse("Unable to register (unknown)")));
  }

  @override
  CallbackStatus onTicketReceived(KernelResponse kernelResponse) {
    EasyLoading.dismiss();
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.Register)) {
      RegisterResponse resp = kernelResponse.getDSR().value;
      if (resp.success) {
        print("[Register Handler] SUCCESS!");
        this.info.sendPort.send(RegisterUISignal(RegisterUpdateSignalType.RegisterSuccess, message: kernelResponse.getMessage().orElse("Successfully registered!")));
      } else {
        this.onErrorReceived(kernelResponse);
      }
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

}