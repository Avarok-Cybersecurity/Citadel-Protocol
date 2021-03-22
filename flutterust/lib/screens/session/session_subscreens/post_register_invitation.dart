import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/default_widget.dart';
import 'package:flutterust/database/notification_subtypes/post_register.dart';
import 'package:flutterust/handlers/accept_post_register.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';

class PostRegisterInvitation extends StatelessWidget {
  final PostRegisterNotification args;

  const PostRegisterInvitation(this.args);

  @override
  Widget build(BuildContext context) {
    return DefaultPageWidget(
        title: Text("Invitation from ${args.peerUsername}"),
        child: Table(
            children: [
              TableRow(
                  children: [
                    Column(
                        children: [
                          Padding(
                              padding: EdgeInsets.all(10),
                              child: Text("${args.peerUsername} would like to register to ${args.implicatedCid}",
                                  style: TextStyle(
                                      fontWeight: FontWeight.bold
                                  )
                              )
                          )
                        ]
                    ),

                    Column(
                      children: [
                        Padding(
                          padding: EdgeInsets.all(10),
                          child: IconButton(
                            icon: Icon(
                              Icons.check_circle,
                              color: Colors.green,
                            ),
                            onPressed: () => handle(true, context),
                          ),
                        )
                      ],
                    ),

                    Column(
                      children: [
                        Padding(
                          padding: EdgeInsets.all(10),
                          child: IconButton(
                            icon: Icon(
                                Icons.not_interested,
                                color: Colors.red
                            ),
                            onPressed: () => handle(false, context),
                          ),
                        )
                      ],
                    )
                  ]
              ),
            ]
        )
    );
  }

  void handle(bool accept, BuildContext ctx) async {
    final String cmd = accept ? "accept-register" : "deny-register";

      (await AutoLogin.executeCommandRequiresConnected(this.args.implicatedCid, "switch ${this.args.implicatedCid.toString()} peer $cmd --fcm ${this.args.peerCid.toString()}"))
          .ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp, handler: AcceptPostRegisterHandler(this.args.implicatedCid, this.args.peerCid, this.args.peerUsername)));

    await this.args.delete();
    Navigator.of(ctx).pop();
  }

}