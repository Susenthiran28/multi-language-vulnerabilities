// File:    VulnerableService.swift
// Purpose: SAST fixture. Swift command/SQL injection, insecure transport,
//          weak crypto, insecure local storage and embedded credentials.
//          Intentionally vulnerable - never ship.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
//
// Expected CWEs: 78, 89, 319, 327, 295, 798, 338, 22, 312.

import CommonCrypto
import Foundation

// CWE-798: credentials in source
let apiKey = "ak_live_swift_0123456789abcdef"
let dbPassword = "Pr0dPassw0rd!"

enum VulnerableService {

    // CWE-78: command injection
    static func ping(host: String) throws {
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", "ping -c 1 \(host)"]
        try task.run()
    }

    // CWE-89: SQL injection
    static func findUserQuery(email: String) -> String {
        return "SELECT id, email FROM users WHERE email = '\(email)'"
    }

    static func execute(db: OpaquePointer?, email: String) {
        let sql = "SELECT id FROM users WHERE email = '\(email)'"
        var stmt: OpaquePointer?
        sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        sqlite3_step(stmt)
        sqlite3_finalize(stmt)
    }

    // CWE-319: cleartext transport
    static func fetchProfile(id: String, completion: @escaping (Data?) -> Void) {
        let url = URL(string: "http://api.internal.example.com/profile/\(id)")!
        URLSession.shared.dataTask(with: url) { data, _, _ in completion(data) }.resume()
    }

    // CWE-327: broken hashing
    static func hashPassword(_ password: String) -> String {
        let data = Data(password.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // CWE-338: predictable token
    static func sessionToken() -> String {
        return String(arc4random_uniform(100000))
    }

    // CWE-312: secrets written to plaintext local storage
    static func cacheCredentials(token: String) {
        UserDefaults.standard.set(token, forKey: "auth_token")
        UserDefaults.standard.set(dbPassword, forKey: "db_password")
    }

    // CWE-22: path traversal
    static func readReport(name: String) throws -> Data {
        return try Data(contentsOf: URL(fileURLWithPath: "/srv/files/\(name)"))
    }
}

// CWE-295: certificate validation disabled
final class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
