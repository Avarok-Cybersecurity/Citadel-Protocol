import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class RegisterResponse extends DomainSpecificResponse {
  final bool success;
  final Ticket ticket;
  final String message;

  RegisterResponse._(this.success, this.ticket, this.message);

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
    return DomainSpecificResponseType.Register;
  }

  static Optional<DomainSpecificResponse> tryFrom(Map<String, dynamic> infoNode) {
    //String DSRRegisterTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Register\",\"Failure\":[2,\"Invalid username\"]}}";
    bool success = infoNode.containsKey("Success");
    List<dynamic> leaf = infoNode[success ? "Success" : "Failure"];
    if (leaf.length != 2) {
      return Optional.empty();
    }

    var ticket = Ticket.tryFrom(leaf[0]);
    String message = leaf[1];

    return ticket.isPresent ? Optional.of(RegisterResponse._(success, ticket.value, message)) : Optional.empty();
  }
}