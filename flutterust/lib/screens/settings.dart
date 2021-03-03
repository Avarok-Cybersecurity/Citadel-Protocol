import 'package:flutter/material.dart';
import 'package:flutterust/database_handler.dart';
import 'package:flutterust/main.dart';

class SettingsScreen extends StatefulWidget {
  static const String routeName = "/settings";
  static const int IDX = 3;
  const SettingsScreen({Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return SettingsScreenInner();
  }

}

class SettingsScreenInner extends State<StatefulWidget> {
  @override
  Widget build(BuildContext context) {
    return Container(
            child: Align(
              alignment: Alignment.bottomCenter,
              child: Row(
                  children: [
                    Expanded(
                      child: ElevatedButton.icon(
                        style: ButtonStyle(
                            backgroundColor: MaterialStateProperty.all(Colors.red)
                        ),
                        icon: Icon(Icons.delete_outline),
                        label: Text("Purge local accounts"),
                        onPressed: purgeAccounts,
                      )
                    )
                  ],
              ),
            )
    );
  }


  void purgeAccounts() async {
    await RustSubsystem.bridge.executeCommand("deregister --purge");
    await ClientNetworkAccount.resyncClients();
  }
}