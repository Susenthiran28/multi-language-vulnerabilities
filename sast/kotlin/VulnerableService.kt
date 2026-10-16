// File:    VulnerableService.kt
// Purpose: SAST fixture. Kotlin/Spring service with SQL and command injection,
//          unsafe deserialization, SSRF, weak crypto and embedded credentials.
//          Intentionally vulnerable - never deploy.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
//
// Expected CWEs: 89, 78, 502, 918, 22, 327, 798, 601, 79, 338, 295.

package com.vigilnz.fixtures

import java.io.ObjectInputStream
import java.net.URL
import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import java.sql.Connection
import java.util.Random
import javax.servlet.http.HttpServletResponse
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class VulnerableService(
    private val jdbc: JdbcTemplate,
    private val connection: Connection
) {

    companion object {
        // CWE-798: credentials in source
        const val DB_PASSWORD = "Pr0dPassw0rd!"
        const val API_KEY = "ak_live_kotlin_0123456789abcdef"
    }

    // CWE-89: SQL injection
    @GetMapping("/user")
    fun findUser(@RequestParam email: String): List<Map<String, Any>> =
        jdbc.queryForList("SELECT id, email FROM users WHERE email = '$email'")

    @GetMapping("/order")
    fun findOrder(@RequestParam id: String): Boolean {
        val stmt = connection.createStatement()
        return stmt.execute("SELECT * FROM orders WHERE id = $id")
    }

    // CWE-78: command injection
    @GetMapping("/ping")
    fun ping(@RequestParam host: String): String =
        Runtime.getRuntime().exec("ping -c 1 $host").inputStream.bufferedReader().readText()

    @GetMapping("/archive")
    fun archive(@RequestParam dir: String): Process =
        ProcessBuilder("sh", "-c", "tar -czf /tmp/out.tgz $dir").start()

    // CWE-502: deserialization of untrusted input
    @PostMapping("/state")
    fun loadState(blob: ByteArray): Any =
        ObjectInputStream(blob.inputStream()).readObject()

    // CWE-918: SSRF
    @GetMapping("/proxy")
    fun proxy(@RequestParam url: String): String = URL(url).readText()

    // CWE-22: path traversal
    @GetMapping("/download")
    fun download(@RequestParam name: String): ByteArray =
        Files.readAllBytes(Paths.get("/srv/files/$name"))

    // CWE-327: broken hashing
    fun hashPassword(password: String): ByteArray =
        MessageDigest.getInstance("MD5").digest(password.toByteArray())

    // CWE-338: predictable token
    fun sessionToken(): String = java.lang.Long.toHexString(Random().nextLong())

    // CWE-79 and CWE-601
    @GetMapping("/greet")
    fun greet(@RequestParam name: String, @RequestParam next: String, response: HttpServletResponse): String {
        response.setHeader("X-Greeting", name)
        response.sendRedirect(next)
        return "<h1>Hello $name</h1>"
    }
}
