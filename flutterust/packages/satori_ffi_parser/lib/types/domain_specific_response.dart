import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/dsr/get_accounts_response.dart';
import 'package:satori_ffi_parser/types/dsr/get_active_sessions.dart';
import 'package:satori_ffi_parser/types/dsr/peer_list.dart';
import 'package:satori_ffi_parser/types/root/domain_specific.dart';

import 'domain_specific_response_type.dart';
import 'dsr/register_response.dart';
import 'kernel_response.dart';
import 'ticket.dart';
import 'package:optional/optional.dart';

abstract class DomainSpecificResponse {
  DomainSpecificResponseType getType();
  Optional<Ticket> getTicket();
  Optional<String> getMessage();

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    try {
      String typeString = infoNode["dtype"];

      DomainSpecificResponseType dType = DomainSpecificResponseType.values.firstWhere((element) => element.toString().split('.').last == typeString);
      print("dType: " + dType.toString());

      switch (dType) {
        case DomainSpecificResponseType.GetActiveSessions:
          return GetSessionsResponse.tryFrom(infoNode);

        case DomainSpecificResponseType.GetAccounts:
          return GetAccountsResponse.tryFrom(infoNode);

        case DomainSpecificResponseType.PeerList:
          return PeerListResponse.tryFrom(infoNode);

        case DomainSpecificResponseType.Register:
          return RegisterResponse.tryFrom(infoNode);

        case DomainSpecificResponseType.Connect:
          return ConnectResponse.tryFrom(infoNode);

        case DomainSpecificResponseType.Disconnect:
          return DisconnectResponse.tryFrom(infoNode);

        default:
          return Optional.empty();
      }
    } catch(_) {}

    return Optional.empty();
  }
}

typedef void Callback(KernelResponse kernelResponse);