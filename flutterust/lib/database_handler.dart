import 'package:optional/optional.dart';
import 'package:path/path.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:sqflite/sqflite.dart';

class DatabaseHandler {

  static Future<Database> database() async {
    return openDatabase(
        join(await getDatabasesPath(), 'verisend.db'),
      onCreate: (db, version) {
        // Run the CREATE TABLE statement on the database.
        return db.execute(
          "CREATE TABLE cnacs(id TEXT PRIMARY KEY, username TEXT, fullName TEXT, isPersonal INTEGER , creationDate TEXT)",
        );
      },
      // Set the version. This executes the onCreate function and provides a
      // path to perform database upgrades and downgrades.
      version: 3,
    );
  }

  static Future<void> clearDatabase() async {
    await deleteDatabase(join(await getDatabasesPath(), 'verisend.db'));
  }

  static void insertClients(List<ClientNetworkAccount> cnacs) async {
    // Get a reference to the database.
    final Database db = await database();

    Batch batch = db.batch();
    cnacs.forEach((element) {
      batch.insert(ClientNetworkAccount.DB_TABLE, element.toMap(), conflictAlgorithm: ConflictAlgorithm.replace);
    });

    var results = await batch.commit();

    print("[INSERT] Result: " + results.toString());
  }

  static void insertClient(ClientNetworkAccount cnac) async {
    // Get a reference to the database.
    final Database db = await database();

    // Insert the Dog into the correct table. You might also specify the
    // `conflictAlgorithm` to use in case the same dog is inserted twice.
    //
    // In this case, replace any previous data.
    var result = await db.insert(
      ClientNetworkAccount.DB_TABLE,
      cnac.toMap(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );

    print("[INSERT] Result: " + result.toString());
  }

}

class ClientNetworkAccount {
  static const String DB_TABLE = "cnacs";
  
  final u64 implicatedCid;
  final String username;
  final String fullName;
  final bool isPersonal;
  final String creationDate;

  ClientNetworkAccount(this.implicatedCid, this.username, this.fullName, this.isPersonal, this.creationDate);

  Map<String, dynamic> toMap() {
    return {
      'id': this.implicatedCid.toString(),
      'username': this.username,
      'fullName': this.fullName,
      'isPersonal': this.isPersonal ? 1 : 0,
      'creationDate': this.creationDate
    };
  }

  static ClientNetworkAccount fromMap(Map<String, dynamic> sqlMap) {
    return ClientNetworkAccount(u64.tryFrom(sqlMap["id"]).value, sqlMap["username"], sqlMap["fullName"], sqlMap["isPersonal"] == 1, sqlMap["creationDate"]);
  }
  
  static Future<Optional<u64>> getCidByUsername(String username) async {
    var db = await DatabaseHandler.database();
    
    var query = await db.query(ClientNetworkAccount.DB_TABLE, where: "username = ?", whereArgs: [username]);
    if (query.length > 0) {
      return Optional.of(u64.tryFrom(query.first["id"].toString()).value);
    } else {
      return Optional.empty();
    }
  }

  static Future<Optional<String>> getUsernameByCid(u64 cid) async {
    return (await getCnacByCid(cid)).map((res) => res.username);
  }

  static Future<Optional<ClientNetworkAccount>> getCnacByCid(u64 cid) async {
    var db = await DatabaseHandler.database();

    var query = await db.query(ClientNetworkAccount.DB_TABLE, where: "id= ?", whereArgs: [cid.toString()]);
    if (query.length > 0) {
      return Optional.of(ClientNetworkAccount.fromMap(query.first));
    } else {
      return Optional.empty();
    }
  }

}