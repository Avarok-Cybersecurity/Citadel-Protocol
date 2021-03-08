import 'package:bubble/bubble.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/default_widget.dart';
import 'package:flutterust/components/text_form_field.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/themes/default.dart';

class MessagingScreen extends StatefulWidget {
  final ClientNetworkAccount implicatedCnac;
  final PeerNetworkAccount peerNac;
  final List<MessageNotification> initMessages;

  MessagingScreen(this.implicatedCnac, this.peerNac, this.initMessages, {Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return MessagingScreenInner();
  }
}

class MessagingScreenInner extends State<MessagingScreen> {
  final TextEditingController messageField = TextEditingController();
  List<Bubble> bubbles;
  BubbleStyle stylePeer;
  BubbleStyle styleSelf;

  MessagingScreenInner();

  @override
  Widget build(BuildContext context) {
    double pixelRatio = MediaQuery.of(context).devicePixelRatio;
    double px = 1 / pixelRatio;

    this.stylePeer = BubbleStyle(
      nip: BubbleNip.leftTop,
      color: Colors.white,
      elevation: 1 * px,
      margin: BubbleEdges.only(top: 8.0, right: 50.0),
      alignment: Alignment.topLeft,
    );

    this.styleSelf = BubbleStyle(
      nip: BubbleNip.rightTop,
      color: Color.fromARGB(255, 225, 255, 199),
      elevation: 1 * px,
      margin: BubbleEdges.only(top: 8.0, left: 50.0),
      alignment: Alignment.topRight,
    );

    return DefaultPageWidget(
        title: Text("Quantum-Secure Communication Channel"),
        child: Container(
          color: primary().shade100,
          child: ListView(

          ),
        ),

      bottomSheet: Align(
        alignment: Alignment.bottomCenter,
        child: Row(
          children: [
            Expanded(
                child: DefaultTextFormField(true, "Message ...")
            )
          ],
        ),
      ),
    );
  }

  /// This function requires that the initMessages have messages TO/FROM the implicated CNAC.
  /// If a message's recipient is the implicated CIDs, then the recipient cid should be nonzero
  /// If a message's recipient is not the implicated CID's (implying sent outbound), the recipient cid should be zero (while the peer cid nonzero)
  void updateChatList({MessageNotification newNotification}) {
    if (this.bubbles != null) {
      if (newNotification != null) {
        print("Pushing new notification into chat ...");
        this.bubbles.add(Bubble(
          child: Text(newNotification.message),
          style: newNotification.recipient == this.widget.implicatedCnac.implicatedCid ? stylePeer : styleSelf,
        ));
      }
    } else {
      // create init bubble list
      this.bubbles = this.widget.initMessages.map((e) => Bubble(
        child: Text(e.message),
        style: e.recipient == this.widget.implicatedCnac.implicatedCid ? stylePeer : styleSelf,
      )).toList();
    }
  }
}