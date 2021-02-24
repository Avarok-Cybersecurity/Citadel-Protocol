import 'package:flutter/material.dart';

class DefaultTextFormField extends StatefulWidget {
  final bool preserveState;
  final String labelText;
  final bool isPassword;
  final TextEditingController controller;
  final bool isFilled;
  final Color fillColor;

  DefaultTextFormField(this.preserveState, this.labelText, {Key key, this.isPassword = false, this.isFilled = false, this.fillColor = Colors.white, this.controller}) : super(key: key);
  
  @override
  State<StatefulWidget> createState() => _DefaultTextFormField(this.preserveState, this.labelText, this.isPassword, this.controller, this.isFilled, this.fillColor);

}

class _DefaultTextFormField extends State<DefaultTextFormField> {
  String value = "";
  String labelText;
  bool isPassword;
  TextEditingController controller;
  bool filled = false;
  Color fillColor;
  
  _DefaultTextFormField(bool preserveState, String labelText, bool isPassword, TextEditingController controller, bool filled, Color fillColor) {
    this.labelText = labelText;
    this.isPassword = isPassword;
    this.controller = controller;
    this.filled = filled;
    this.fillColor = fillColor;
    print("Filled? " + filled.toString());
  }
  
  @override
  Widget build(BuildContext context) {
    return TextFormField(
      controller: this.controller,
      obscureText: this.isPassword,
      decoration: InputDecoration(
        labelText: this.labelText,
        filled: this.filled,
        fillColor: this.fillColor
      ),

      onSaved: (_value) {
        print("onSaved called (val: " + _value + ")");
      },
    );
  }

}