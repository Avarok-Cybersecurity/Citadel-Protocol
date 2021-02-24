import 'dart:io';
import 'dart:typed_data';

import 'package:optional/optional.dart';

Iterable<List<T>> zip<T>(Iterable<Iterable<T>> iterables) sync* {
  if (iterables.isEmpty) return;
  final iterators = iterables.map((e) => e.iterator).toList(growable: false);
  while (iterators.every((e) => e.moveNext())) {
    yield iterators.map((e) => e.current).toList(growable: false);
  }
}

/// Maps a list of T's to a list of U's
List<U> filterMap<T, U>(Iterable<T> list, {Optional<U> transform(T t)}) {
  if (transform != null) {
    return list.map((t) => transform(t)).where((tOpt) => tOpt.isPresent).map((t) => t.value).toList(growable: false);
  } else {
    return list.where((t) => t is U).map((t) => t as U).toList(growable: false);
  }
}

bool sameLengths<T>(Iterable<Iterable<T>> lists) {
  if (lists.length != 0) {
    var base = lists.elementAt(0);
    for (var value in lists) {
      if (value.length != base.length) {
        return false;
      }
    }

    return true;
  } else {
    return true;
  }
}

Optional<InternetAddress> tryParseAddr<T>(T input) {
  print("Endpoint transform of " + input.toString());
  return Optional.ofNullable(InternetAddress.tryParse(input.toString()));
}

Optional<int> tryParseInt<T>(T input) {
  if (input is String) {
    return Optional.ofNullable(int.tryParse(input));
  } else {
    return Optional.empty();
  }
}