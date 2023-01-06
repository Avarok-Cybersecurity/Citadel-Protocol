
import 'package:optional/optional.dart';

class Result<T, E> {
  final Optional<T> value;
  final Optional<E> error;

  Result.ok(T t) : this.value = Optional.of(t), this.error = Optional.empty();
  Result.err(E e) : this.value = Optional.empty(), this.error = Optional.of(e);

  bool isOk() => this.value.isPresent;
  bool isErr() => this.error.isPresent;

  T unwrap() => this.value.value;
  E unwrapErr() => this.error.value;

  @override
  bool operator == (Object other) {
    if (other is Result<T, E>) {
      if (other.isOk() && this.isOk()) {
        return other.unwrap() == this.unwrap();
      }

      if (other.isErr() && this.isErr()) {
        return other.unwrapErr() == this.unwrapErr();
      }

      // if one is err and other is ok, return false always
      return false;
    } else {
      return false;
    }
  }

  @override
  int get hashCode => this.isOk() ? this.unwrap().hashCode : this.unwrapErr().hashCode;

}