
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

class NestSafeGestureDetector extends StatelessWidget {
  final Widget child;
  final void Function() onTap;

  NestSafeGestureDetector(this.onTap, this.child);

  @override
  Widget build(BuildContext context) {
    return RawGestureDetector(
      gestures: {
        AllowMultipleGestureRecognizer: GestureRecognizerFactoryWithHandlers<
            AllowMultipleGestureRecognizer>(
              () => AllowMultipleGestureRecognizer(),
              (AllowMultipleGestureRecognizer instance) {
            instance.onTap = this.onTap;
          },
        )
      },
      behavior: HitTestBehavior.opaque,
      child: this.child,
    );
  }

}


class AllowMultipleGestureRecognizer extends TapGestureRecognizer {
  @override
  void rejectGesture(int pointer) {
    acceptGesture(pointer);
  }
}