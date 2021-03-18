
import 'dart:collection';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class SecureStorageHandler {
  static final secureStorage = FlutterSecureStorage();
  static const String USERNAME_KEY = "USERNAME_";
  static const String PASSWORD_KEY = "PASSWORD_";
  static const String SECURITY_LEVEL_KEY = "SECURITY_LEVEL_";

  static Future<void> saveCredentials(Credentials creds) async {
    await secureStorage.write(key: USERNAME_KEY + creds.username, value: creds.username);
    await secureStorage.write(key: PASSWORD_KEY + creds.username, value: creds.password);
    await secureStorage.write(key: SECURITY_LEVEL_KEY + creds.username, value: creds.securityLevel.toString());
  }

  static Future<void> deleteCredentialsFor(String username) async {
    await secureStorage.delete(key: USERNAME_KEY + username);
    await secureStorage.delete(key: PASSWORD_KEY + username);
    await secureStorage.delete(key: SECURITY_LEVEL_KEY + username);
  }

  static Future<void> deleteAll() async {
    await secureStorage.deleteAll();
  }

  static Future<Optional<Credentials>> getCredentialsByUsername(String username) async {
    String uname = await secureStorage.read(key: USERNAME_KEY + username);
    if (uname != null) {
      String password = await secureStorage.read(key: PASSWORD_KEY + username);
      if (password != null) {
        String secLevel = await secureStorage.read(key: SECURITY_LEVEL_KEY + username);
        if (secLevel != null) {
          int val = int.tryParse(secLevel);
          if (val != null) {
            return Optional.of(Credentials(uname, password, val));
          }
        }
      }
    }

    return Optional.empty();
  }

  static Future<List<Credentials>> getAutologinAccounts(List<ClientNetworkAccount> localAccounts) async {
    return await Stream.fromIterable(localAccounts).asyncMap((localAccount) async => await getCredentialsByUsername(localAccount.username))
        .where((val) => val.isPresent).map((val) => val.value).toList();
  }
}

class Credentials {
  final String username;
  final String password;
  final int securityLevel;

  Credentials(this.username, this.password, this.securityLevel);
}