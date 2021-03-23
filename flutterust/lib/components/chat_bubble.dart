import 'package:flutter/material.dart';

class DefaultBubble extends StatelessWidget {
  DefaultBubble({required this.message, required this.time, required this.icon, required this.iconColorPeer, required this.iconColorMe, required this.isMe, required this.onTap, Key? key}) : super(key: key);

  final String message, time;
  final bool isMe;
  final IconData icon;
  final Color? iconColorPeer;
  final Color? iconColorMe;
  final void Function() onTap;

  @override
  Widget build(BuildContext context) {
    final bg = isMe ? Colors.blue : Color(0xffE7E7ED);
    final align = isMe ? CrossAxisAlignment.end : CrossAxisAlignment.start;

    final radius = isMe
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
            onTap: this.onTap,
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
                      message,
                      style: TextStyle(
                          color: this.isMe ? Colors.white : Colors.black
                      ),
                    ),
                  ),

                  Positioned(
                    bottom: 0.0,
                    right: 0.0,
                    child: Row(
                      children: <Widget>[
                        Text(time,
                            style: TextStyle(
                              color: Colors.black38,
                              fontSize: 10.0,
                            )),
                        SizedBox(width: 3.0),
                        Icon(
                          icon,
                          size: 12.0,
                          color: this.isMe ? (this.iconColorMe ?? Colors.black38) : (this.iconColorPeer ?? Colors.black38),
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