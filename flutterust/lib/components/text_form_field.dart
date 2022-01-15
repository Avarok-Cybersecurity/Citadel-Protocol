import 'package:flutter/material.dart';

class DefaultTextFormField extends StatefulWidget {
  final bool preserveState;
  final String? labelText;
  final bool isPassword;
  final TextEditingController controller;
  final bool isFilled;
  final Color fillColor;
  final String? hintText;

  DefaultTextFormField(this.preserveState, this.labelText, {Key? key, this.isPassword = false, this.isFilled = false, this.fillColor = Colors.white, required this.controller, this.hintText}) : super(key: key);
  
  @override
  State<StatefulWidget> createState() => _DefaultTextFormField();

}

class _DefaultTextFormField extends State<DefaultTextFormField> {
  
  @override
  Widget build(BuildContext context) {
    return TextFormField(
      controller: this.widget.controller,
      obscureText: this.widget.isPassword,
      decoration: InputDecoration(
        labelText: this.widget.labelText,
        filled: this.widget.isFilled,
        fillColor: this.widget.fillColor,
        hintText: this.widget.hintText
      ),

      onSaved: (_value) {
        if (_value is String)
        print("onSaved called (val: " + _value + ")");
      },
    );
  }

}