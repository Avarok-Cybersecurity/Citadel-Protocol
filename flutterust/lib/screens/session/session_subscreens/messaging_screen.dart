import 'dart:async';

import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/chat_bubble.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/utils.dart';
import 'package:intl/intl.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:optional/optional.dart';
import 'package:rxdart/rxdart.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MessagingScreen extends StatefulWidget {
  final ClientNetworkAccount implicatedCnac;
  final PeerNetworkAccount peerNac;

  final TextEditingController messageField = TextEditingController();
  final List<Widget> bubbles = [];

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
    print(
        "Loaded ${initMessages.length} messages between ${this.widget.implicatedCnac.implicatedCid} and ${this.widget.peerNac.peerCid}");
    this.initMessageCount = initMessages.length;

    for (Message message in initMessages) {
      yield MessageWidgetUpdateStore.insert(
          bubbleFrom(message, message.status));
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
          bubbleFrom(message, message.status))),
      this.initStream()
    ]).map((message) {
      print("[MERGE] Stream recv");

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
          print("[MERGE/REPLACE] altering idx ${message.idx}");
          this.widget.bubbles[message.idx] = message.bubble.value;
          break;
      }

      return ListView(
        key: UniqueKey(),
        controller: this._scrollController,
        keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
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
      Message message = this.constructMessageInstance(text);
      this
          .sendIntake
          .sink
          .add(MessageWidgetUpdateStore.insert(bubbleFrom(message)));
      await message.sync();

      String command = this.widget.peerNac.peerCid == u64.zero
          ? "switch ${this.widget.implicatedCnac.implicatedCid} send $text"
          : "switch ${this.widget.implicatedCnac.implicatedCid} peer send ${this.widget.peerNac.peerUsername} --fcm $text";

      await AutoLogin.executeCommandRequiresConnected(
              this.widget.implicatedCnac.implicatedCid,
              command,
              username: this.widget.implicatedCnac.username)
          .then((value) => value.ifPresent((kResp) =>
              KernelResponseHandler.handleFirstCommand(kResp,
                  handler: PeerSendHandler(onMessageStatusUpdateSent, message,
                      this.widget.bubbles.length - 1),
                  oneshot: false)));
      this.widget.messageField.clear();
    }
  }

  void onMessageStatusUpdateSent(PeerSendUpdate update) {
    print("onMessageStatusUpdateSent called");
    this.sendIntake.add(MessageWidgetUpdateStore.replace(
        bubbleFrom(update.message, update.state), update.messageIdxInChat));
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

  Widget bubbleFrom(Message message, [PeerSendState state = PeerSendState.Unprocessed, Key? key]) {
    return DefaultBubble(
      key: key ?? UniqueKey(),
      message: message.message,
      time: DateFormat.jm().format(message.recvTime),
      icon: getAppropriateIconByCheckCount(state),
      iconColorMe: state == PeerSendState.MessageReceived ? Colors.lightGreenAccent : null,
      iconColorPeer: Colors.blueAccent,
      isMe: !message.fromPeer,
      onTap: () => print("onTap called for $message"),
    );
  }

  IconData getAppropriateIconByCheckCount(PeerSendState state) {
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
  final Optional<Widget> bubble;
  final MessageWidgetUpdate type;
  final int idx;

  MessageWidgetUpdateStore(this.bubble, this.type, this.idx);

  MessageWidgetUpdateStore.clear()
      : this(Optional.empty(), MessageWidgetUpdate.Clear, -1);

  MessageWidgetUpdateStore.insert(Widget bubble)
      : this(Optional.of(bubble), MessageWidgetUpdate.New, -1);

  MessageWidgetUpdateStore.replace(Widget bubble, int idx)
      : this(Optional.of(bubble), MessageWidgetUpdate.Replace, idx);
}
