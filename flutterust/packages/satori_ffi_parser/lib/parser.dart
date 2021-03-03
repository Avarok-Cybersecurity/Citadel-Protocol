import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/root/domain_specific.dart';
import 'package:satori_ffi_parser/types/root/fcm_ticket.dart';
import 'package:satori_ffi_parser/types/root/kernel_shutdown.dart';

import 'types/kernel_response.dart';
import 'package:optional/optional.dart';
import 'dart:convert';

import 'types/kernel_response_type.dart';
import 'types/root/confirmation.dart';
import 'types/root/error.dart';
import 'types/root/hybrid.dart';
import 'types/root/message.dart';
import 'types/root/node_message.dart';
import 'types/root/ticket.dart';
import 'types/standard_ticket.dart';

const MessageParseMode DEFAULT_PARSE_MODE = MessageParseMode.UTF8;

enum MessageParseMode {
  None, UTF8
}

class FFIParser {

  /// By default, any strings passed from the kernel are encoded in base64 to allow the application to decide whether to interpret the string as utf-8 or utf-16
  static Optional<KernelResponse> tryFrom(String inputJson, { MessageParseMode mapBase64Strings = DEFAULT_PARSE_MODE }) {
    try {
      Map<String, dynamic> outerNode = json.decode(inputJson);
      String typeString = outerNode["type"];

      KernelResponseType type = KernelResponseType.values.firstWhere((element) => element.toString().split('.')[1] == typeString);
      print("[Parser] Found type: " + type.toString());
      var infoNode = outerNode["info"];
      print("[Parser] infoNode: " + infoNode.toString());

      switch (type) {
        case KernelResponseType.Confirmation:
          return Optional.of(ConfirmationKernelResponse());

        case KernelResponseType.Message:
          return Optional.of(MessageKernelResponse(mapBase64(infoNode, mapBase64Strings)));

        case KernelResponseType.ResponseTicket:
          return StandardTicket.tryFrom(infoNode).map((ticket) => TicketKernelResponse(ticket));

        case KernelResponseType.ResponseHybrid:
          return HybridKernelResponse.tryFrom(infoNode, mapBase64Strings);

        case KernelResponseType.NodeMessage:
          return NodeMessageKernelResponse.tryFrom(infoNode, mapBase64Strings);

        case KernelResponseType.DomainSpecificResponse:
          return DomainSpecificResponse.tryFrom(infoNode, mapBase64Strings).map((dsr) => DomainSpecificKernelResponse(dsr));

        case KernelResponseType.Error:
          return ErrorKernelResponse.tryFromStd(infoNode, mapBase64Strings);

        case KernelResponseType.FcmError:
          return ErrorKernelResponse.tryFromFcm(infoNode, mapBase64Strings);

        case KernelResponseType.ResponseFcmTicket:
          return FcmTicketResponse.tryFrom(infoNode);

        case KernelResponseType.KernelShutdown:
          return KernelShutdown.tryFrom(infoNode, mapBase64Strings);
      }

    } catch (e) {
      print("Invalid input Json: " + e.toString());
      return Optional.empty();
    }
  }

  //static Optional<KernelResponse> parseHybridResponse(List<>)
}

bool isNumeric(String s) {
  print("parse: " + double.tryParse(s).toString());
  return s != null ? double.tryParse(s) != null : false;
}

String mapBase64(String value, MessageParseMode mode) {
  switch (mode) {
    case MessageParseMode.None:
      return value;
    case MessageParseMode.UTF8:
      return Utf8Decoder().convert(base64.decode(value));
  }
}