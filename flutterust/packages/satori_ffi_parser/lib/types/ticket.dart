import 'package:satori_ffi_parser/types/u64.dart';

abstract class Ticket {
  u64 get id;
  bool eq(Ticket other);
  bool operator == (o) => eq(o);
}