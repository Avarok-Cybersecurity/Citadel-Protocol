import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

import '../u64.dart';

class ConnectResponse extends DomainSpecificResponse {
  String message;
  Ticket ticket;
  u64 implicated_cid;
  bool success;
  Optional<String> username;

  ConnectResponse._(bool success, Ticket ticket, u64 implicated_cid, String message) {
    this.message = message;
    this.ticket = ticket;
    this.implicated_cid = implicated_cid;
    this.success = success;
  }

  @override
  Optional<String> getMessage() {
    return Optional.of(this.message);
  }

  @override
  Optional<Ticket> getTicket() {
    return Optional.of(this.ticket);
  }

  @override
  DomainSpecificResponseType getType() {
    return DomainSpecificResponseType.Connect;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    bool success = infoNode.containsKey("Success");
    List<dynamic> leaf = infoNode[success ? "Success" : "Failure"];
    if (leaf.length != 3) {
      return Optional.empty();
    }

    var ticket = Ticket.tryFrom(leaf[0]);
    var implicated_cid = u64.tryFrom(leaf[1]);
    String message = leaf[2];

    return ticket.isPresent && implicated_cid.isPresent ? Optional.of(ConnectResponse._(success, ticket.value, implicated_cid.value, message)) : Optional.empty();
  }

  void attachUsername(String username) {
    this.username = Optional.of(username);
  }

  Optional<String> getAttachedUsername() {
    return this.username;
  }
}