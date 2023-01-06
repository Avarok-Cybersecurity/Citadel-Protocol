import 'package:optional/optional.dart';

class GuiCallback {
  Optional<void Function(dynamic)> function;

  GuiCallback._(this.function);
  GuiCallback.empty() : this._(Optional.empty());

  void registerCallback(void Function(dynamic) func) {
    this.function = Optional.of(func);
  }

  bool call(dynamic input) {
    if (this.function.isPresent) {
      this.function.value.call(input);
      return true;
    } else {
      return false;
    }
  }
}