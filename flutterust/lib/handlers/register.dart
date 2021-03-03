import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/database_handler.dart';
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
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) async {
    await EasyLoading.dismiss();
    print("[Register Handler] Registration failed: " + kernelResponse.message);
    onError(kernelResponse.message);
  }

  void onError(String err) async {
    await EasyLoading.dismiss();
    this.info.sendPort.send(RegisterUISignal(RegisterUpdateSignalType.RegisterFailure, message: err));
  }

  @override
  CallbackStatus onTicketReceived(KernelResponse kernelResponse) {
    EasyLoading.dismiss();
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.Register)) {
      RegisterResponse resp = kernelResponse.getDSR().value;
      if (resp.success) {
        print("[Register Handler] SUCCESS!");
        ClientNetworkAccount.resyncClients();
        this.info.sendPort.send(RegisterUISignal(RegisterUpdateSignalType.RegisterSuccess, message: kernelResponse.getMessage().orElse("Successfully registered!")));
      } else {
        this.onError(kernelResponse.getMessage().value);
      }
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

}