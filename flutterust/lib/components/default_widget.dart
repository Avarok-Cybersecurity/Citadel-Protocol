
import 'package:flutter/material.dart';

class DefaultPageWidget extends StatelessWidget {
  final Widget child;
  final Widget title;
  final EdgeInsets padding;
  final Alignment align;
  final Widget bottomSheet;

  const DefaultPageWidget({@required this.title, @required this.child, this.align, this.padding = const EdgeInsets.all(20), this.bottomSheet});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
          title: title
      ),

      body: this.align != null ? getAlignBody() : getDefaultBody(),
      bottomSheet: this.bottomSheet,
    );
  }

  Widget getDefaultBody() {
    return Center(
        child: Container(
          padding: padding,
          child: SingleChildScrollView(
              physics: BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
              child: child
          ),
        ));
  }

  Widget getAlignBody() {
    return Align(
      alignment: this.align,
      child: Container(
        padding: padding,
        child: SingleChildScrollView(
            physics: BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
            child: child
        ),
      ),
    );
  }

}