import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class Ticket {
  u64 id;

  Ticket(u64 id) {
    this.id = id;
  }

  static Optional<Ticket> tryFrom<T>(T input) {
    if (input is String) {
      var id = u64.tryFrom(input);
      if (id.isPresent) {
        if (id.value != u64.zero) {
          return Optional.of(Ticket(id.value));
        }
      }
    }

    return Optional.empty();
  }

  bool operator == (o) => o is Ticket && id == o.id;

  @override
  String toString() {
    return "Ticket(" + this.id.toString() + ")";
  }

  @override
  int get hashCode => this.id.hashCode;
}