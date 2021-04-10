import 'dart:async';

import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/chat_bubble.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/misc/message_send_handler.dart';
import 'package:flutterust/utils.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:optional/optional.dart';
import 'package:rxdart/rxdart.dart';

class MessagingScreen extends StatefulWidget {
  final ClientNetworkAccount implicatedCnac;
  final PeerNetworkAccount peerNac;

  final TextEditingController messageField = TextEditingController();
  final List<DefaultBubble> bubbles = [];

  MessagingScreen(this.implicatedCnac, this.peerNac, {Key? key})
      : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return new MessagingScreenInner();
  }
}

class MessagingScreenInner extends State<MessagingScreen> {

  ScrollController _scrollController = ScrollController();
  late final Stream<Widget> messageStream;
  StreamController<MessageWidgetUpdateStore> sendIntake = StreamController();
  int initMessageCount = 0;

  Stream<MessageWidgetUpdateStore> initStream() async* {
    print("initStream executed");
    var initMessages = await Message.getMessagesBetween(
        this.widget.implicatedCnac.implicatedCid, this.widget.peerNac.peerCid);

    print("Loaded ${initMessages.length} messages between ${this.widget.implicatedCnac.implicatedCid} and ${this.widget.peerNac.peerCid}");
    this.initMessageCount = initMessages.length;

    for (Message message in initMessages) {
      yield MessageWidgetUpdateStore.insert(
          bubbleFrom(message, false, state: message.status));
    }
  }

  @override
  void initState() {
    super.initState();
    Utils.currentlyOpenedMessenger =
        Optional.of(this.widget.implicatedCnac.implicatedCid);

    this.messageStream = Rx.merge([
      sendIntake.stream,
      Utils.broadcaster.stream.stream
          .where((message) =>
      this.widget.implicatedCnac.implicatedCid ==
          message.implicatedCid &&
          this.widget.peerNac.peerCid == message.peerCid)
          .map((message) => MessageWidgetUpdateStore.insert(
          bubbleFrom(message, false, state: message.status))),
      this.initStream()
    ]).map((message) {
      print("[MERGE] Stream recv TYPE ${message.type}");

      switch (message.type) {
        case MessageWidgetUpdate.New:
          this.widget.bubbles.add(message.bubble.value);
          this._scrollController = _scrollController.hasClients
              ? ScrollController(
              initialScrollOffset:
              _scrollController.position.maxScrollExtent)
              : ScrollController();
          break;

        case MessageWidgetUpdate.Clear:
          this.widget.bubbles.clear();
          this._scrollController = ScrollController();
          break;

        case MessageWidgetUpdate.Replace:
          print("[MERGE/REPLACE] altering idx");
          //this.widget.bubbles[message.idx] = message.bubble.value;
          //var state = message.bubble.value.messageState;
          //this.widget.bubbles[message.idx].updateValues(getAppropriateIconByCheckCount(state), state == PeerSendState.MessageReceived ? Colors.lightGreenAccent : null);
          break;
      }

      print("Bubble len: ${this.widget.bubbles.length}");

      return ListView(
        key: UniqueKey(),
        controller: this._scrollController,
        keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.manual,
        padding: EdgeInsets.only(top: 10, left: 10, right: 10, bottom: 50),
        children: this.widget.bubbles,
      );
    });
  }

  @override
  void dispose() {
    super.dispose();
    this.sendIntake.close();
    Utils.currentlyOpenedMessenger = Optional.empty();
  }

  Widget compileWidget(BuildContext context) {
    final stream = this.messageStream;
    return StreamBuilder(
        stream: stream,
        builder: (context, snapshot) {
          print(
              "[StreamBuilder] Refresh. Current Bubbles:  ${this.widget.bubbles.length} && ${snapshot.connectionState}");
          if (snapshot.hasData) {
            WidgetsBinding.instance!.addPostFrameCallback((timeStamp) {
              this.scrollToBottom();
            });

            print("DONE loading widget (${this.widget.bubbles.length} items)");
            return snapshot.data as Widget;
          } else {
            if (this.initMessageCount != 0) {
              return Container(
                child: Center(child: CircularProgressIndicator()),
              );
            } else {
              return Center(
                child: Text("No messages yet ..."),
              );
            }
          }
        });
  }

  @override
  Widget build(BuildContext context) {
    print("build called on messenger");
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            CircleAvatar(
                backgroundImage:
                    CachedNetworkImageProvider(this.widget.peerNac.avatarUrl)),
            VerticalDivider(),
            Text(
              "${this.widget.peerNac.peerUsername}",
              style: TextStyle(height: 1),
            )
          ],
        ),
        actions: [
          PopupMenuButton<String>(
            onSelected: onSettingsPressed,
            itemBuilder: (BuildContext context) {
              return {"Clear"}.map((String choice) {
                return PopupMenuItem<String>(
                  value: choice,
                  child: Text(choice),
                );
              }).toList();
            },
          )
        ],
      ),
      body: compileWidget(context),
      bottomSheet: Row(
        children: [
          Expanded(
              child: DefaultTextFormField(true, null,
                  hintText: "Message ...",
                  controller: this.widget.messageField)),
          IconButton(icon: Icon(Icons.send), onPressed: onSendPressed)
        ],
      ),
    );
  }

  void onSettingsPressed(String cmd) async {
    switch (cmd.toLowerCase()) {
      case "clear":
        await Message.deleteAll(this.widget.implicatedCnac.implicatedCid,
            this.widget.peerNac.peerCid);
        this.sendIntake.sink.add(MessageWidgetUpdateStore.clear());
    }
  }

  void onSendPressed() async {
    String text = this.widget.messageField.text;
    print("Text: $text");
    if (text.isNotEmpty) {
      print(
          "Going to send '$text' from ${this.widget.implicatedCnac.username} to ${this.widget.peerNac.peerUsername}");
      //var position = this.widget.bubbles.length;
      Message message = this.constructMessageInstance(text);
      this
          .sendIntake
          .sink
          .add(MessageWidgetUpdateStore.insert(bubbleFrom(message, true)));
      //await message.sync();

      this.widget.messageField.clear();
    }
  }

  void onMessageStatusUpdateSent(PeerSendUpdate update) {
    print("onMessageStatusUpdateSent called");
    this.sendIntake.add(MessageWidgetUpdateStore.replace(
        bubbleFrom(update.message, false, state: update.state)));
    //this.widget.bubbles[update.messageIdxInChat].updateValues(getAppropriateIconByCheckCount(update.state), update.state == PeerSendState.MessageReceived ? Colors.lightGreenAccent : null);
  }

  Message constructMessageInstance(String messageOut) {
    return Message(
        this.widget.implicatedCnac.implicatedCid,
        this.widget.peerNac.peerCid,
        messageOut,
        DateTime.now(),
        false,
        PeerSendState.Unprocessed,
        null
    );
  }

  DefaultBubble bubbleFrom(Message message, bool needsSend, {PeerSendState state = PeerSendState.Unprocessed}) {
    return DefaultBubble(
      parentList: this.widget.bubbles,
      key: UniqueKey(),
      message: message,
        icon: getAppropriateIconByCheckCount(message.status),
        iconColorMe: message.status == PeerSendState.MessageReceived ? Colors.lightGreenAccent : null,
      iconColorPeer: Colors.blueAccent,
      onTap: () => MessageSendHandler.pollSpecificChannel(message, bubbles: this.widget.bubbles),
      needsSend: needsSend
    );
  }

  static IconData getAppropriateIconByCheckCount(PeerSendState state) {
    switch (state) {
      case PeerSendState.Unprocessed:
        return Icons.hourglass_bottom;
      case PeerSendState.MessageSent:
        return Icons.done;
      case PeerSendState.MessageReceived:
        return Icons.done_all;
      case PeerSendState.Failure:
        return MdiIcons.alertCircle;
    }
  }

  void scrollToBottom() {
    if (this._scrollController.hasClients) {
      this._scrollController.animateTo(
            this._scrollController.position.maxScrollExtent,
            curve: Curves.easeOut,
            duration: const Duration(milliseconds: 300),
          );
    }
  }
}

enum MessageWidgetUpdate { New, Replace, Clear }

class MessageWidgetUpdateStore {
  final Optional<DefaultBubble> bubble;
  final MessageWidgetUpdate type;

  MessageWidgetUpdateStore(this.bubble, this.type);

  MessageWidgetUpdateStore.clear()
      : this(Optional.empty(), MessageWidgetUpdate.Clear);

  MessageWidgetUpdateStore.insert(DefaultBubble bubble)
      : this(Optional.of(bubble), MessageWidgetUpdate.New);

  MessageWidgetUpdateStore.replace(DefaultBubble bubble)
      : this(Optional.of(bubble), MessageWidgetUpdate.Replace);
}
