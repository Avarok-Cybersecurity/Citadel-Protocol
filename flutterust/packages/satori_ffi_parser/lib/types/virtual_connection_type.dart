import 'package:optional/optional.dart';

enum VirtualConnectionType {
  HyperLANPeerToHyperLANServer,
  HyperLANPeerToHyperLANPeer,
  HyperLANPeerToHyperWANServer,
  HyperLANPeerToHyperWANPeer
}

Optional<VirtualConnectionType> findFirstInKeys(Map<String, dynamic> map) {
  String found = map.keys.firstWhere((element) => VirtualConnectionType.values.any((val) => val.toString().split(".").last == element), orElse: () => "");
  return found != "" ? Optional.of(VirtualConnectionType.values.firstWhere((element) => element.toString().split(".").last == found)) : Optional.empty();
}