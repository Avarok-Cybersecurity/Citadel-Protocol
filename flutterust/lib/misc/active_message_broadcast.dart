import 'dart:async';

import 'package:flutterust/database/message.dart';

/// This is really only for active
class MessageStreamer {
  final StreamController<Message> stream;

  MessageStreamer() : this.stream = StreamController.broadcast();

  void subscribe(void Function(Message) listener) {
    this.stream.stream.listen(listener);
  }

  void broadcast(Message message) {
    this.stream.sink.add(message);
  }
}