import 'dart:async';

import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutter_chat_bubble/bubble_type.dart';
import 'package:flutter_chat_bubble/chat_bubble.dart';
import 'package:flutter_chat_bubble/clippers/chat_bubble_clipper_1.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/utils.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:optional/optional.dart';
import 'package:rxdart/rxdart.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MessagingScreen extends StatefulWidget {
  final ClientNetworkAccount implicatedCnac;
  final PeerNetworkAccount peerNac;

  final TextEditingController messageField = TextEditingController();
  final List<Widget> bubbles = [];

  MessagingScreen(this.implicatedCnac, this.peerNac, {Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return new MessagingScreenInner();
  }
}

class MessagingScreenInner extends State<MessagingScreen> {


  ScrollController _scrollController = ScrollController();
  Stream<Widget> messageStream;
  StreamController<Message> sendIntake = StreamController();
  int initMessageCount = 0;
  //StreamSubscription<dynamic> messageListener;


  Stream<Message> initStream() async* {
    print("initStream executed");
    var initMessages = await Message.getMessagesBetween(this.widget.implicatedCnac.implicatedCid, this.widget.peerNac.peerCid);
    print("Loaded ${initMessages.length} messages between ${this.widget.implicatedCnac.implicatedCid} and ${this.widget.peerNac.peerCid}");
    this.initMessageCount = initMessages.length;

    for (Message message in initMessages) {
      yield message;
    }
  }

  @override
  void initState() {
    super.initState();
    Utils.currentlyOpenedMessenger = Optional.of(this.widget.implicatedCnac.implicatedCid);

    this.messageStream = Rx.merge<Message>([sendIntake.stream, Utils.broadcaster.stream.stream.where((message) => this.widget.implicatedCnac.implicatedCid == message.implicatedCid && this.widget.peerNac.peerCid == message.peerCid), this.initStream()]).map((message) {
      if (message != null) {
        print("[MERGE] stream recv $message");
        this.widget.bubbles.add(Container(key: UniqueKey(), child: bubbleFrom(message)));
        this._scrollController = _scrollController.hasClients ? ScrollController(initialScrollOffset:  _scrollController.position.maxScrollExtent) : ScrollController();
      } else {
        this.widget.bubbles.clear();
        this._scrollController = ScrollController();
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
    this.messageStream = null;
    this.sendIntake.close();
    Utils.currentlyOpenedMessenger = Optional.empty();
  }

  Widget compileWidget(BuildContext context) {
    final stream = this.messageStream;
    return StreamBuilder(
      stream: stream,
        builder: (context, snapshot) {
        print("[StreamBuilder] Refresh. Current Bubbles:  ${this.widget.bubbles.length} && ${snapshot.connectionState}");
          if (snapshot.hasData) {
            WidgetsBinding.instance.addPostFrameCallback((timeStamp) {
              this.scrollToBottom();
            });

            print("DONE loading widget (${this.widget.bubbles.length} items)");
            return snapshot.data;
          } else {
            if (this.initMessageCount != 0) {
              return Container(
                child: Center(
                    child: CircularProgressIndicator()
                ),
              );
            } else {
              return Center(
                child: Text("No messages yet ..."),
              );
            }
          }
        }
    );
  }

  @override
  Widget build(BuildContext context) {
    print("build called on messenger");
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            CircleAvatar(
                backgroundImage: CachedNetworkImageProvider(this.widget.peerNac.avatarUrl)
            ),

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
              child: DefaultTextFormField(true, null, hintText: "Message ...", controller: this.widget.messageField)
          ),

          IconButton(
              icon: Icon(Icons.send),
              onPressed: onSendPressed
          )
        ],
      ),
    );
  }

  void onSettingsPressed(String cmd) async {
    switch (cmd.toLowerCase()) {
      case "clear":
        await Message.deleteAll(this.widget.implicatedCnac.implicatedCid, this.widget.peerNac.peerCid);
        this.sendIntake.sink.add(null);
    }

    setState(() {});
  }

  void onSendPressed() async {
    String text = this.widget.messageField.text;
    print("Text: $text");
    if (text.isNotEmpty) {
      print("Going to send '$text' from ${this.widget.implicatedCnac.username} to ${this.widget.peerNac.peerUsername}");
      Message message = this.constructMessageInstance(text);
      this.sendIntake.sink.add(message);
      await message.sync();

      String command = this.widget.peerNac.peerCid == u64.zero ? "switch ${this.widget.implicatedCnac.implicatedCid} send $text" : "switch ${this.widget.implicatedCnac.implicatedCid} peer send ${this.widget.peerNac.peerUsername} --fcm $text";

      await AutoLogin.executeCommandRequiresConnected(this.widget.implicatedCnac.implicatedCid, this.widget.implicatedCnac.username, command)
      .then((value) => value.ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp, handler: PeerSendHandler(onMessageStatusUpdateSent, message, this.widget.bubbles.length - 1), oneshot: false)));
      this.widget.messageField.clear();
    }
  }

  void onMessageStatusUpdateSent(PeerSendUpdate update) {
    print("onMessageStatusUpdateSent called");
    setState(() {
      this.widget.bubbles[update.messageIdxInChat] = bubbleFrom(update.message, update.state);
    });
  }

  Message constructMessageInstance(String messageOut) {
    return Message(this.widget.implicatedCnac.implicatedCid, this.widget.peerNac.peerCid, messageOut, DateTime.now(), false, PeerSendState.Unprocessed);
  }

  ChatBubble bubbleFrom(Message message, [ PeerSendState state = PeerSendState.Unprocessed ]) {
    if (message.fromPeer) {
      return ChatBubble(
        clipper: ChatBubbleClipper1(type: BubbleType.receiverBubble),
        backGroundColor: Color(0xffE7E7ED),
        margin: EdgeInsets.all(10),
        child: Container(
          constraints: BoxConstraints(
            maxWidth: MediaQuery.of(context).size.width * 0.7,
          ),
          child: Padding(
            padding: EdgeInsets.symmetric(horizontal: 10),
            child: Stack(
              children: [
                Text(
                  message.message,
                  style: TextStyle(color: Colors.black),
                ),

                Align(
                  alignment: Alignment.bottomRight,
                  child: getAppropriateIconByCheckCount(state),
                )
              ],
            )
          ),
        ),
      );
    } else {
      return ChatBubble(
        clipper: ChatBubbleClipper1(type: BubbleType.sendBubble),
        alignment: Alignment.topRight,
        margin: EdgeInsets.all(10),
        backGroundColor: Colors.blue,
        child: Container(
          constraints: BoxConstraints(
            maxWidth: MediaQuery.of(context).size.width * 0.7,
          ),
          child: Padding(
            padding: EdgeInsets.symmetric(horizontal: 10),
            child: Stack(
              children: [
                Text(
                  message.message,
                  style: TextStyle(color: Colors.white),
                ),

                Align(
                  alignment: Alignment.bottomRight,
                  child: getAppropriateIconByCheckCount(state),
                )
              ],
            )
          ),
        ),
      );
    }
  }

  Widget getAppropriateIconByCheckCount(PeerSendState state) {
    switch (state) {
      case PeerSendState.Unprocessed:
        return const Icon(MdiIcons.timerSandEmpty);
      case PeerSendState.MessageSent:
        return const Icon(MdiIcons.check);
      case PeerSendState.MessageReceived:
        return const Icon(MdiIcons.checkAll);
      case PeerSendState.Failure:
        return const Icon(MdiIcons.alertCircle);
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