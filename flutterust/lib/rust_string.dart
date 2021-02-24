import 'package:optional/optional.dart';
import 'package:scrap/scrap.dart';

class RustString {
  Optional<String> value;
  FFIBridge scrap;

  RustString(String value, FFIBridge scrap) {
    this.value = Optional.of(value);
    this.scrap = scrap;
  }

  Optional<String> getString() {
    return this.value;
  }

  /// This should be manually called onc
  void memfree() {
    if (this.value.isPresent) {
      this.scrap.memfree(this.value.value);
      this.value = Optional.empty();
    }
  }

}