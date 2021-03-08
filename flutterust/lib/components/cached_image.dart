
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/peer_network_account.dart';

class DefaultCachedImage extends CachedNetworkImage {
  DefaultCachedImage({ @required String imageUrl, BoxFit fit = BoxFit.cover }) : super(imageUrl: imageUrl, imageBuilder: (context, imageProvider) => Container(
    decoration: BoxDecoration(
      image: DecorationImage(
          image: imageProvider,
          fit: fit
      ),
    ),
  ),
  placeholder: (context, url) => CircularProgressIndicator(),
  errorWidget: (context, url, error) => Icon(Icons.error));


  DefaultCachedImage.fromCnac(ClientNetworkAccount cnac, {BoxFit fit}) : this(imageUrl: cnac.avatarUrl, fit: fit);
  DefaultCachedImage.fromPeerNac(PeerNetworkAccount peerNac, {BoxFit fit}) : this(imageUrl: peerNac.avatarUrl, fit: fit);



}