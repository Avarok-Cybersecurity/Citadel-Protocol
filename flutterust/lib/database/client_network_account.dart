import 'package:flutterust/database/abstract_sql_object.dart';
import 'package:flutterust/database/database_handler.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/dsr/get_accounts_response.dart';
import 'package:satori_ffi_parser/types/u64.dart';

import '../globals.dart';

class ClientNetworkAccount extends AbstractSqlObject {
  static const String DB_TABLE = "cnacs";
  static const String GENESIS = "CREATE TABLE $DB_TABLE (id TEXT NOT NULL PRIMARY KEY, username TEXT, fullName TEXT, isPersonal INTEGER , creationDate TEXT, avatarUrl TEXT)";

  final u64 implicatedCid;
  final String username;
  final String fullName;
  final bool isPersonal;
  final String creationDate;
  final String avatarUrl;

  const ClientNetworkAccount(this.implicatedCid, this.username, this.fullName,
      this.isPersonal, this.creationDate, { this.avatarUrl = DEFAULT_AVATAR_IMAGE });

  ClientNetworkAccount.fromMap(Map<String, dynamic> sqlMap) :
        this.implicatedCid = u64.tryFrom(sqlMap["id"]).value,
        this.username = sqlMap["username"],
        this.fullName = sqlMap["fullName"],
        this.isPersonal = sqlMap["isPersonal"] == 1,
        this.creationDate = sqlMap["creationDate"],
        this.avatarUrl = sqlMap["avatarUrl"];

  @override
  Map<String, dynamic> toMap() {
    return {
      'id': this.implicatedCid.toString(),
      'username': this.username,
      'fullName': this.fullName,
      'isPersonal': this.isPersonal ? 1 : 0,
      'creationDate': this.creationDate,
      'avatarUrl': this.avatarUrl
    };
  }

  static Future<Optional<u64>> getCidByUsername(String username) async {
    return DatabaseHandler.getKeyByFieldValue(ClientNetworkAccount.DB_TABLE, "username", username, (rawKey) => u64.tryFrom(rawKey).value);
  }

  static Future<Optional<String>> getUsernameByCid(u64 cid) async {
    return (await getCnacByCid(cid)).map((res) => res.username);
  }

  static Future<Optional<ClientNetworkAccount>> getCnacByCid(u64 cid) async {
    return DatabaseHandler.getObjectByID(ClientNetworkAccount.DB_TABLE, cid.toString(), (sqlMap) => ClientNetworkAccount.fromMap(sqlMap));
  }

  static Future<int> resyncClients() async {
    return (await RustSubsystem.bridge.executeCommand("list-accounts"))
        .map((kResp) {
      return kResp.getDSR().map((dsr) async {
        if (dsr is GetAccountsResponse) {
          print("Found " + dsr.cids.length.toString() + " local accounts");
          if (dsr.cids.isEmpty) {
            // clear the database just incase there are lingering clients
            await DatabaseHandler.clearDatabase();
            await SecureStorageHandler.deleteAll();
            return 0;
          } else {
            List<ClientNetworkAccount> cnacs = zip([
              dsr.cids,
              dsr.usernames,
              dsr.full_names,
              dsr.is_personals,
              dsr.creation_dates
            ]).map((e) => ClientNetworkAccount(e[0], e[1], e[2], e[3], e[4]))
                .toList(growable: false);

            await DatabaseHandler.upsertObjects(cnacs);

            // Also, add the default PeerNetworkAccounts for the peerCid of zero (representing a client/server communication session, useful for community messages)
            await DatabaseHandler.upsertObjects(dsr.cids.map((e) => PeerNetworkAccount(u64.from(0), e, "Community")).toList(growable: false));
            // additionally, get a list of clients that have autologin enabled
            await AutoLogin.setupAutologin(cnacs);
            return dsr.cids.length;
          }
        }
      }).orElse(Future.value(-1));
    }).orElse(Future.value(-1));
  }

  @override
  String getTableName() {
    return DB_TABLE;
  }

  @override
  Optional getDatabaseKey() {
    return Optional.of(this.implicatedCid.toString());
  }
}