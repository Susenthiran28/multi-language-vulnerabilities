/*
 * File:    VulnerableServlet.java
 * Purpose: SAST fixture. Java servlet with SQL/command/LDAP injection, XXE,
 *          unsafe deserialization, SSRF, path traversal and weak crypto.
 *          Intentionally vulnerable - never deploy.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected CWEs: 89, 78, 90, 611, 502, 918, 22, 327, 798, 601, 79, 338.
 */

package com.vigilnz.fixtures;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Random;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class VulnerableServlet extends HttpServlet {

    // CWE-798: credentials in source
    private static final String DB_PASSWORD = "Pr0dPassw0rd!";
    private static final String API_KEY = "ak_live_java_0123456789abcdef";

    private Connection connection;
    private DirContext ldapContext;

    // CWE-89: SQL injection
    public ResultSet findUser(HttpServletRequest request) throws Exception {
        Statement stmt = connection.createStatement();
        String sql = "SELECT id, email FROM users WHERE email = '" + request.getParameter("email") + "'";
        return stmt.executeQuery(sql);
    }

    // CWE-78: command injection
    public Process ping(HttpServletRequest request) throws IOException {
        return Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("host"));
    }

    public Process build(HttpServletRequest request) throws IOException {
        return new ProcessBuilder("sh", "-c", "tar -czf /tmp/out.tgz " + request.getParameter("dir")).start();
    }

    // CWE-90: LDAP injection
    public void findByName(HttpServletRequest request) throws Exception {
        String filter = "(cn=" + request.getParameter("name") + ")";
        ldapContext.search("ou=users,dc=vigilnz,dc=com", filter, new SearchControls());
    }

    // CWE-611: XXE - external entity resolution left enabled
    public void parseUpload(HttpServletRequest request) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(request.getInputStream());
    }

    // CWE-502: deserialization of untrusted input
    public Object loadState(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();
    }

    // CWE-918: SSRF
    public int proxy(HttpServletRequest request) throws IOException {
        URL url = new URL(request.getParameter("url"));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        return conn.getResponseCode();
    }

    // CWE-22: path traversal
    public byte[] download(HttpServletRequest request) throws IOException {
        return Files.readAllBytes(Paths.get("/srv/files/" + request.getParameter("name")));
    }

    // CWE-327: broken hashing
    public byte[] hashPassword(String password) throws Exception {
        return MessageDigest.getInstance("MD5").digest(password.getBytes());
    }

    // CWE-338: predictable token
    public String sessionToken() {
        return Long.toHexString(new Random().nextLong());
    }

    // CWE-79 and CWE-601
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + request.getParameter("name") + "</h1>");
        response.sendRedirect(request.getParameter("next"));
    }
}
