
import 'package:flutterust/database/abstract_sql_object.dart';
import 'package:flutterust/database/database_handler.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notification_subtypes/notification_message.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:sqflite/sqflite.dart';

/// Unlike its AbstractNotification counterpart, this is meant for long-term storage
class Message extends AbstractSqlObject {
  static const String DB_TABLE = "messages";
  static const String GENESIS = "CREATE TABLE $DB_TABLE (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, implicatedCid TEXT, peerCid TEXT, message TEXT, recvTime TEXT, fromPeer INTEGER, status TEXT, rawTicket TEXT)";

  final u64 implicatedCid;
  final u64 peerCid;
  final String message;
  final DateTime recvTime;
  final bool fromPeer;
  u64? rawTicket;
  PeerSendState status;
  int? _id;

  Message(this.implicatedCid, this.peerCid, this.message, this.recvTime, this.fromPeer, this.status, this.rawTicket);
  Message.fromMap(Map<String, dynamic> sql) :
      this.implicatedCid = u64.tryFrom(sql["implicatedCid"]).value,
  this.peerCid = u64.tryFrom(sql["peerCid"]).value,
  this.message = sql["message"],
  this.recvTime = DateTime.parse(sql["recvTime"]),
  this.status = PeerSendStateExt.fromString(sql["status"]).value,
  this.fromPeer = sql["fromPeer"] == 1,
  this.rawTicket = u64.tryFrom(sql["rawTicket"]).value;

  @override
  Optional getDatabaseKey() {
    return Optional.ofNullable(this._id);
  }

  @override
  String getTableName() {
    return DB_TABLE;
  }

  @override
  Map<String, dynamic> toMap() {
    return {
      'implicatedCid': this.implicatedCid.toString(),
      'peerCid': this.peerCid.toString(),
      'message': this.message,
      'recvTime': this.recvTime.toIso8601String(),
      'fromPeer': this.fromPeer ? 1 : 0,
      'status' : this.status.asString(),
      'rawTicket': this.rawTicket.toString()
    };
  }

  @override
  Future<int> sync({ConflictAlgorithm conflictAlgorithm = ConflictAlgorithm.replace}) async {
    this._id = await super.sync(conflictAlgorithm: conflictAlgorithm);
    return this._id!;
  }

  static Future<List<Message>> getMessagesBetween(u64 implicatedCid, u64 peerCid) async {
    return await DatabaseHandler.getObjectsByBidirectionalConditional(DB_TABLE, "implicatedCid", implicatedCid.toString(), "peerCid", peerCid.toString(), (val) => Message.fromMap(val));
  }

  AbstractNotification toAbstractNotification() {
    if (this.fromPeer) {
      return MessageNotification(this.implicatedCid, this.peerCid, this.message, this.recvTime, true, this.status, this.rawTicket);
    } else {
      return MessageNotification(this.peerCid, this.implicatedCid, this.message, this.recvTime, false, this.status, this.rawTicket);
    }
  }

  static Future<int> deleteAll(u64 implicatedCid, u64 peerCid) async {
    return await DatabaseHandler.removeAllByBidirectionalConditional(DB_TABLE, "implicatedCid", implicatedCid.toString(), "peerCid", peerCid.toString());
  }

  static Future<Optional<Message>> getMessage(u64 implicatedCid, u64 peerCid, u64 rawTicket) async {
    return await DatabaseHandler.getObjectByTriconditional(DB_TABLE, "implicatedCid", implicatedCid.toString(), "peerCid", peerCid.toString(), "rawTicket", rawTicket.toString(), (map) => Message.fromMap(map));
  }

  @override
  String toString() {
    return "[$recvTime] $implicatedCid <-> $peerCid: $message [fromPeer: $fromPeer]";
  }
}