import 'package:optional/optional.dart';

class u64 {
  static final u64 zero = u64(BigInt.zero);
  static final u64 one = u64(BigInt.one);
  static final u64 two = u64(BigInt.two);
  static final u64 MIN = zero;
  static final u64 MAX = u64(BigInt.tryParse("18446744073709551615"));

  BigInt id;

  u64(BigInt id) {
    this.id = id;
  }

  u64.from(num id) {
    this.id = BigInt.from(id);
  }

  static Optional<u64> tryFrom<T>(T input) {
    if (input is String) {
      BigInt id = BigInt.tryParse(input);
      if (id != null) {
        if (id >= BigInt.zero && id <= MAX.id) {
          return Optional.of(u64(id.toUnsigned(64)));
        }
      }
    }

    return Optional.empty();
  }

  static List<u64> fromList(List<dynamic> list) {
    return list.map((e) => u64.tryFrom(e)).where((element) => element.isPresent).map((e) => e.value).toList(growable: false);
  }

  bool operator == (o) => o is u64 && o.id == id;

  bool operator > (o) => o is u64 && id > o.id;
  bool operator < (o) => o is u64 && id < o.id;

  @override
  String toString() {
    return this.id.toString();
  }

  @override
  int get hashCode => this.id.hashCode;
}