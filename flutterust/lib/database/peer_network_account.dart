import 'package:flutterust/database/abstract_sql_object.dart';
import 'package:flutterust/database/database_handler.dart';
import 'package:flutterust/globals.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/u64.dart';

// for mutually-connected peers
class PeerNetworkAccount extends AbstractSqlObject {
  static const String DB_TABLE = "peers";
  static const String GENESIS = "CREATE TABLE $DB_TABLE (id TEXT NOT NULL PRIMARY KEY, implicatedCid TEXT, peerUsername TEXT, avatarUrl TEXT)";

  final u64 peerCid;
  final u64 implicatedCid;
  final String peerUsername;
  final String avatarUrl;

  const PeerNetworkAccount(this.peerCid, this.implicatedCid, this.peerUsername, { this.avatarUrl = DEFAULT_AVATAR_IMAGE });

  @override
  Map<String, dynamic> toMap() {
    return {
      'id': this.getDatabaseKey().value,
      'implicatedCid': this.implicatedCid.toString(),
      'peerUsername': this.peerUsername,
      'avatarUrl': this.avatarUrl
    };
  }

  PeerNetworkAccount.fromMap(final Map<String, dynamic> sqlMap)
      : this.peerCid = u64.tryFrom(sqlMap["id"].toString().split(".").first).value,
        this.implicatedCid = u64.tryFrom(sqlMap["implicatedCid"]).value,
        this.peerUsername = sqlMap["peerUsername"],
        this.avatarUrl = sqlMap["avatarUrl"];

  static Future<Optional<PeerNetworkAccount>> getPeerByCid(u64 implicatedCid, u64 peerCid) async {
    return await DatabaseHandler.getObjectByID(PeerNetworkAccount.DB_TABLE, _getKeyFrom(implicatedCid, peerCid), (map) => PeerNetworkAccount.fromMap(map));
  }

  static Future<Optional<u64>> getCidByUsername(String username) async {
    return await DatabaseHandler.getKeyByFieldValue(PeerNetworkAccount.DB_TABLE, "peerUsername", username, (key) => u64.tryFrom(key).value);
  }

  static Future<List<PeerNetworkAccount>> listAllForImplicatedCid(u64 implicatedCid) async {
    return await DatabaseHandler.getObjectsByFieldValue(PeerNetworkAccount.DB_TABLE, "implicatedCid", implicatedCid.toString(), (sqlMap) => PeerNetworkAccount.fromMap(sqlMap)).then((value) => value.orElse([]));
  }

  @override
  String getTableName() {
    return DB_TABLE;
  }

  @override
  Optional<String> getDatabaseKey() {
    return Optional.of(_getKeyFrom(this.implicatedCid, this.peerCid));
  }

  static String _getKeyFrom(u64 implicatedCid, u64 peerCid) {
    return peerCid.toString() + "." + implicatedCid.toString();
  }
}