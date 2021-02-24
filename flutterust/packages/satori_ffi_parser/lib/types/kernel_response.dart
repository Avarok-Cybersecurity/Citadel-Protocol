import 'domain_specific_response.dart';
import 'kernel_response_type.dart';
import 'ticket.dart';
import 'package:optional/optional.dart';

abstract class KernelResponse {
  Optional<Callback> _action = Optional.empty();
  bool _oneshot = true;
  bool _callbackRetrieved = false;

  Optional<Ticket> getTicket();
  KernelResponseType getType();
  Optional<String> getMessage();
  Optional<DomainSpecificResponse> getDSR();

  Optional<Callback> getCallbackAction() {
    if (this._oneshot && this._callbackRetrieved) {
      return Optional.empty();
    }

    this._callbackRetrieved = true;
    return this._action;
  }

  void setCallbackAction(Callback action) {
    this._action = Optional.of(action);
  }

  /// If set, the callback can only be called once
  void setOneshot(bool oneshot) {
    this._oneshot = oneshot;
  }

  bool isOneshot() {
    return this._oneshot;
  }
}