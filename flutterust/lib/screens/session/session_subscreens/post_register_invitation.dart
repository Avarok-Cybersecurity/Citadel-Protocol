import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_request.dart';

class PostRegisterInvitation extends StatelessWidget {
  static String routeName = "/post-register-invitation";
  const PostRegisterInvitation();

  @override
  Widget build(BuildContext context) {
    final PostRegisterRequest args = ModalRoute.of(context).settings.arguments;

    return Center(
        child: Container(
          child: Table(
              children: [
                TableRow(
                    children: [
                      Column(
                          children: [
                            Padding(
                                padding: EdgeInsets.all(10),
                                child: Text("${args.username} would like to register to ${args.implicatedCid}",
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
                              onPressed: () { handle(true, args, context); },
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
                              onPressed: () { handle(false, args, context); },
                            ),
                          )
                        ],
                      )
                    ]
                ),
              ]
          )
        )
      );
  }

  void handle(bool accept, final PostRegisterRequest request, BuildContext ctx) async {
    final String cmd = accept ? "accept-register" : "deny-register";

      (await RustSubsystem.bridge.executeCommand("switch ${request.implicatedCid.toString()} peer $cmd --fcm ${request.peerCid.toString()}"))
          .ifPresent((kResp) { KernelResponseHandler.handleFirstCommand(kResp); });

    // TODO: Make notifications list
    Navigator.of(ctx).pop();
  }

}