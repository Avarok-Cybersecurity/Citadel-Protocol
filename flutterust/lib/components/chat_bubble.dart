import 'package:flutter/material.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/misc/gui_callback.dart';
import 'package:flutterust/misc/message_send_handler.dart';
import 'package:flutterust/screens/session/session_subscreens/messaging_screen.dart';
import 'package:intl/intl.dart';

class DefaultBubble extends StatefulWidget {
  DefaultBubble({required this.message, required this.iconColorPeer, required this.onTap, required this.needsSend, required this.icon, required this.iconColorMe, required this.parentList, Key? key}) :
        this.time =  DateFormat.jm().format(message.initTime),
        this.isMe = !message.fromPeer,
        this.callback = GuiCallback.empty(),
        super(key: key);

  final Message message;
  final String time;
  final bool isMe;
  final IconData icon;
  final Color? iconColorPeer;
  final Color? iconColorMe;
  final void Function() onTap;
  final bool needsSend;
  final List<DefaultBubble> parentList;
  final GuiCallback callback;

  @override
  State<StatefulWidget> createState() {
    return DefaultBubbleImpl(this.icon, this.iconColorMe);
  }

}

class DefaultBubbleImpl extends State<DefaultBubble> {
  IconData currentIcon;
  Color? currentIconColorMe;

  DefaultBubbleImpl(this.currentIcon, this.currentIconColorMe);


  @override
  void initState() {
    super.initState();
    this.widget.callback.registerCallback((input) => onMessageUpdateRecv(input));
    maybeSendMessage();
  }

  Future<void> maybeSendMessage() async {
    await widget.message.update();
    this.updateIcons(widget.message.status);
    if (widget.needsSend && widget.message.status == PeerSendState.Unprocessed) {
      print("[ChatBubble] Sending message ${widget.message}");
      await MessageSendHandler.sendMessageFromScreen(this.widget.message, PeerSendHandler.screen(onMessageUpdateRecv, this.widget.message, this.widget.parentList));
    }
  }

  void onMessageUpdateRecv(PeerSendUpdate update) {
    print("onMessageUpdateRecv triggered for ${this.widget.message} [state: $update]");
    if (this.mounted) {
      setState(() {
        updateIcons(update.state);
      });
    } else {
      print("Not mounted!!");
    }
  }

  void updateIcons(PeerSendState state) {
    this.currentIcon = MessagingScreenInner.getAppropriateIconByCheckCount(state);
    this.currentIconColorMe = state == PeerSendState.MessageReceived ? Colors.lightGreenAccent : null;
  }

  @override
  Widget build(BuildContext context) {
    this.updateIcons(widget.message.status);
    final bg = widget.isMe ? Colors.blue : Color(0xffE7E7ED);
    final align = widget.isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start;

    final radius = widget.isMe
        ? BorderRadius.only(
      topRight: Radius.circular(5.0),
      bottomLeft: Radius.circular(10.0),
      bottomRight: Radius.circular(5.0),
    )
        : BorderRadius.only(
      topLeft: Radius.circular(5.0),
      bottomLeft: Radius.circular(5.0),
      bottomRight: Radius.circular(10.0),
    );

    return Column(
      crossAxisAlignment: align,
      children: <Widget>[
        InkWell(
          onTap: this.widget.onTap,
          child: Container(
            margin: const EdgeInsets.all(3.0),
            padding: const EdgeInsets.all(8.0),
            decoration: BoxDecoration(
              boxShadow: [
                BoxShadow(
                    blurRadius: .5,
                    spreadRadius: 1.0,
                    color: Colors.black.withOpacity(.12))
              ],
              color: bg,
              borderRadius: radius,
            ),
            child: Stack(
              children: <Widget>[
                Padding(
                  padding: EdgeInsets.only(right: 68.0),
                  child: Text(
                    widget.message.message,
                    style: TextStyle(
                        color: widget.isMe ? Colors.white : Colors.black
                    ),
                  ),
                ),

                Positioned(
                  bottom: 0.0,
                  right: 0.0,
                  child: Row(
                    children: <Widget>[
                      Text(widget.time,
                          style: TextStyle(
                            color: Colors.black38,
                            fontSize: 10.0,
                          )),
                      SizedBox(width: 3.0),
                      Icon(
                        this.currentIcon,
                        size: 12.0,
                        color: widget.isMe ? (this.currentIconColorMe ?? Colors.black38) : (widget.iconColorPeer ?? Colors.black38),
                      )
                    ],
                  ),
                )
              ],
            ),
          ),
        )
      ],
    );
  }
}