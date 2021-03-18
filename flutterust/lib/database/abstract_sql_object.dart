import 'package:flutterust/database/database_handler.dart';
import 'package:optional/optional.dart';
import 'package:sqflite/sql.dart';

abstract class AbstractSqlObject {
  const AbstractSqlObject();

  Map<String, dynamic> toMap();
  String getTableName();
  Optional<dynamic> getDatabaseKey();
  
  /// Saves to the database. Returns the id of the row
  Future<dynamic> sync({ConflictAlgorithm conflictAlgorithm}) async {
    return await DatabaseHandler.upsertObject(this);
  }

  Future<bool> delete() async {
    return await this.getDatabaseKey()
    .map((key) => DatabaseHandler.removeObjectById(this.getTableName(), key)).orElse(Future.value(false));
  }
}

extension AbstractSqlObjectExt on List<AbstractSqlObject> {
  Future<List<dynamic>> sync({ConflictAlgorithm conflictAlgorithm}) async {
    return await DatabaseHandler.insertObjects(this, conflictAlgorithm: conflictAlgorithm);
  }

  Future<List<dynamic>> upsert() async {
    return await DatabaseHandler.upsertObjects(this);
  }
}