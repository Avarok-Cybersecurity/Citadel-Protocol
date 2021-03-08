import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class StandardTicket extends Ticket {
  u64 id;

  StandardTicket(u64 id) {
    this.id = id;
  }

  StandardTicket.from(num id) {
    this.id = u64.from(id);
  }

  static Optional<StandardTicket> tryFrom<T>(T input) {
    if (input is String) {
      var id = u64.tryFrom(input);
      if (id.isPresent) {
        if (id.value != u64.zero) {
          return Optional.of(StandardTicket(id.value));
        }
      }
    }

    return Optional.empty();
  }

  bool operator == (o) => o is StandardTicket && id == o.id;

  @override
  String toString() {
    return "StandardTicket(" + this.id.toString() + ")";
  }

  @override
  int get hashCode => this.id.hashCode;

  @override
  bool eq(Ticket other) {
    return other == this;
  }
}