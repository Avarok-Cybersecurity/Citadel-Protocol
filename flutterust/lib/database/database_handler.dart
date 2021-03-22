import 'package:flutterust/database/abstract_sql_object.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:optional/optional.dart';
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';

class DatabaseHandler {
  static const String DB_NAME = "verisend.db";
  // The holy commandments
  static const List<String> genesisCommands = [
    ClientNetworkAccount.GENESIS,
    RawNotification.GENESIS,
    PeerNetworkAccount.GENESIS,
    Message.GENESIS
  ];

  static Future<Database> database() async {
    return openDatabase(
      join(await getDatabasesPath(), DB_NAME),
      onCreate: (db, version) {
        print("About to create database ...");
        // Run the CREATE TABLE statement on the database.
        var batch = db.batch();

        for (var cmd in genesisCommands) {
          batch.rawQuery(cmd);
        }

        return batch.commit().then((_) => {});
      },
      // Set the version. This executes the onCreate function and provides a
      // path to perform database upgrades and downgrades.
      version: 12,
    );
  }

  static Future<void> clearDatabase() async {
    await deleteDatabase(join(await getDatabasesPath(), DB_NAME));
  }

  static Future<int> updateObjectField(String table, dynamic id, String fieldName, dynamic newFieldValue) async {
    final Database db = await database();
    return db.rawUpdate("UPDATE $table SET $fieldName = ? WHERE id = ?", [newFieldValue, id]);
  }

  /// Inserts a row if non-existant. If the entry already exists, updates it
  /// Returns the database key. If key is already supplied, then returns the pre-existing key
  static Future<dynamic> upsertObject(AbstractSqlObject object, {Database databaseInstance}) async {
    final Database db = databaseInstance ?? await database();
    if (object.getDatabaseKey().isPresent) {
      print("Database key present");
      var count = Sqflite.firstIntValue(await db.rawQuery("SELECT COUNT(*) FROM ${object.getTableName()} WHERE id = ?", [object.getDatabaseKey().value]));

      if (count == 0) {
        print("No pre-existing entry for ${object.getDatabaseKey().value}");
        await insertObject(object);
        return object.getDatabaseKey().value;
      } else {
        print("Pre-existing entry for ${object.getDatabaseKey().value} found");
        await updateObject(object);
        return object.getDatabaseKey().value;
      }
    } else {
      print("No database key present, creating one anew (requires AUTOINCREMENT)");
      // insert
      return await insertObject(object);
    }
  }

  static Future<List<dynamic>> upsertObjects(List<AbstractSqlObject> objects) async {
    final Database db = await database();

    return await Stream.fromIterable(objects).asyncMap((object) => upsertObject(object, databaseInstance: db)).toList();
  }
  
  static Future<List<Object>> insertObjects(List<AbstractSqlObject> objects, { ConflictAlgorithm conflictAlgorithm = ConflictAlgorithm.replace }) async {
    // Get a reference to the database.
    final Database db = await database();

    Batch batch = db.batch();

    objects.forEach((element) {
      batch.insert(element.getTableName(), element.toMap(),
          conflictAlgorithm: ConflictAlgorithm.replace);
    });

    var results = await batch.commit();

    print("[INSERT] Result: " + results.toString());
    return results;
  }

  static Future<int> insertObject(AbstractSqlObject object, { ConflictAlgorithm conflictAlgorithm = ConflictAlgorithm.replace }) async {
    // Get a reference to the database.
    final Database db = await database();

    // Insert the Dog into the correct table. You might also specify the
    // `conflictAlgorithm` to use in case the same dog is inserted twice.
    //
    // In this case, replace any previous data.
    var result = await db.insert(
      object.getTableName(),
      object.toMap(),
      conflictAlgorithm: conflictAlgorithm,
    );

    print("[INSERT] Result: " + result.toString());
    return result;
  }

  // WARNING! This should only be called if the database key is already stored within the object.
  // If you do not know, use upsertObject or insertObject
  // Returns the number of "changes made"
  static Future<int> updateObject(AbstractSqlObject object) async {
    // Get a reference to the database.
    final Database db = await database();

    // Insert the Dog into the correct table. You might also specify the
    // `conflictAlgorithm` to use in case the same dog is inserted twice.
    //
    // In this case, replace any previous data.
    var result = await db.update(
      object.getTableName(),
      object.toMap(),
      where: "id = ?",
      whereArgs: [object.getDatabaseKey().value]
    );

    print("[INSERT] Result: " + result.toString());
    return result;
  }


  static Future<Optional<T>> getObjectByID<T>(String table, dynamic id, T Function(Map<String, dynamic>) deserializer) async {
    var db = await DatabaseHandler.database();
    var query = await db.query(table,
        where: "id= ?", whereArgs: [id]);
    if (query.length > 0) {
      return Optional.of(deserializer.call(query.first));
    } else {
      return Optional.empty();
    }
  }

  /// Assumed that the field value is unique
  static Future<Optional<T>> getKeyByFieldValue<T>(String tableName, String fieldName, dynamic fieldValue, T Function(Object) keyMapper) async {
    var db = await DatabaseHandler.database();

    var query = await db.query(tableName,
        where: "$fieldName = ?", whereArgs: [fieldValue]);
    if (query.length > 0) {
      return Optional.of(keyMapper.call(query.first["id"]));
    } else {
      return Optional.empty();
    }
  }

  static Future<Optional<List<T>>> getKeyByIdAndFieldValue<T>(String tableName, dynamic id, String fieldName, dynamic fieldValue, T Function(Object) deserializer) async {
    var db = await DatabaseHandler.database();

    var query = await db.query(tableName,
        where: "id = ? and $fieldName = ?", whereArgs: [id, fieldValue]);
    if (query.length > 0) {
      return Optional.of(query.map((e) => deserializer.call(e)).toList());
    } else {
      return Optional.empty();
    }
  }

  static Future<Optional<List<T>>> getObjectsById<T>(String tableName, dynamic id, T Function(Map<String, dynamic>) deserializer, { bool onlyOne = false }) async {
    return await getObjectsByFieldValue(tableName, "id", id, deserializer, onlyOne: onlyOne);
  }

  static Future<Optional<List<T>>> getObjectsByFieldValue<T>(String tableName, String fieldName, dynamic fieldValue, T Function(Map<String, dynamic>) deserializer, { bool onlyOne = false }) async {
    var db = await DatabaseHandler.database();

    var query = await db.query(tableName,
        where: "$fieldName = ?", whereArgs: [fieldValue]);
    if (query.length > 0) {
      if (onlyOne) {
        return Optional.of([deserializer.call(query.first)]);
      } else {
        return Optional.of(query.map((e) => deserializer.call(e)).toList());
      }
    } else {
      return Optional.empty();
    }
  }
  
  /// Executes ~ SELECT * FROM tableName WHERE (fieldName1 = value1 AND fieldName2 = value2) OR (fieldName1 = value2 AND fieldName2 = value1)
  /// Useful for when searching for an ordered chat log between recipient and sender, where the field values can be in any column
  ///
  /// Note: the deserializer will need to ensure the correct constructor gets called (i.e., the right ordering), since the same deserializer is called uniformly for all obtained rows
  static Future<List<T>> getObjectsByBidirectionalConditional<T>(String tableName, String fieldName1, dynamic value1, String fieldName2, dynamic value2, T Function(Map<String, dynamic>) deserializer) async {
    var db = await DatabaseHandler.database();
    
    var query = await db.rawQuery("SELECT * FROM $tableName WHERE ($fieldName1 = ? AND $fieldName2 = ?) OR ($fieldName1 = ? AND $fieldName2 = ?)", [value1, value2, value2, value1]);
    print("[Bidirectional] Retrieved ${query.length} results");
    return query.map((sqlRowMap) => deserializer.call(sqlRowMap)).toList();
  }

  // Returns true if exactly one value was removed, false otherwise
  static Future<bool> removeObjectById(String tableName, dynamic id) async {
    var db = await DatabaseHandler.database();
    return await db.delete(tableName, where: "id = ?", whereArgs: [id]).then((value) => value == 1);
  }

  static Future<int> removeAllByFieldValue(String tableName, String fieldName, dynamic fieldValue) async {
    var db = await DatabaseHandler.database();
    return await db.delete(tableName, where: "$fieldName = ?", whereArgs: [fieldValue]);
  }

  static Future<bool> removeByTriconditional(String tableName, String fieldName1, dynamic fieldValue1, String fieldName2, dynamic fieldValue2, String fieldName3, dynamic fieldValue3) async {
    var db = await DatabaseHandler.database();
    return await db.delete(tableName, where: "fieldName1 = ? AND fieldName2 = ? AND fieldName3 = ?", whereArgs: [fieldValue1, fieldValue2, fieldValue3]).then((value) => value == 1);
  }

  static Future<Optional<T>> getObjectByTriconditional<T>(String tableName, String fieldName1, dynamic fieldValue1, String fieldName2, dynamic fieldValue2, String fieldName3, dynamic fieldValue3, T Function(Map<String, dynamic>) deserializer) async {
    var db = await DatabaseHandler.database();

    var query = await db.query(tableName, where: "$fieldName1 = ? AND $fieldName2 = ? AND $fieldName3 = ?", whereArgs: [fieldValue1, fieldValue2, fieldValue3]);

    if (query.length != 0) {
      return deserializer.call(query.first).toOptional;
    } else {
      return Optional.empty();
    }
  }

  static Future<int> removeAllByBidirectionalConditional(String tableName, String fieldName1, dynamic fieldValue1, String fieldName2, dynamic fieldValue2) async {
    var db = await DatabaseHandler.database();
    return await db.delete(tableName, where: "($fieldName1 = ? AND $fieldName2 = ?) OR ($fieldName1 = ? AND $fieldName2 = ?)", whereArgs: [fieldValue1, fieldValue2, fieldValue2, fieldValue1]);
  }
}