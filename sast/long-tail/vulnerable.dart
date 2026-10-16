// File:    vulnerable.dart
// Purpose: SAST fixture (Dart). Process spawn, weak hashes, raw SQL,
//          insecure HTTP client, remote isolate loading.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
// Expected rules: dart-process-run, dart-weak-hash, dart-raw-sql,
//   dart-http-client, dart-isolate-spawn-uri

import 'dart:io';
import 'dart:isolate';
import 'package:crypto/crypto.dart';
import 'package:sqflite/sqflite.dart';

Future<ProcessResult> ping(String host) {
  // CWE-78: command injection
  return Process.run('sh', ['-c', 'ping -c 1 $host']);
}

Future<Process> archive(String dir) {
  return Process.start('bash', ['-c', 'tar -czf /tmp/out.tgz $dir']);
}

String hashPassword(String password) {
  // CWE-327: broken hashes
  return md5.convert(password.codeUnits).toString();
}

String fingerprint(List<int> data) => sha1.convert(data).toString();

Future<List<Map<String, Object?>>> findUser(Database db, String email) {
  // CWE-89: SQL injection
  return db.rawQuery("SELECT id, email FROM users WHERE email = '$email'");
}

Future<HttpClientResponse> proxy(String url) async {
  // CWE-295 / CWE-918: certificate validation disabled, URL unvalidated
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  final request = await client.getUrl(Uri.parse(url));
  return request.close();
}

Future<Isolate> loadPlugin(String uri) {
  // CWE-494: code loaded from an unverified location
  return Isolate.spawnUri(Uri.parse(uri), [], null);
}
