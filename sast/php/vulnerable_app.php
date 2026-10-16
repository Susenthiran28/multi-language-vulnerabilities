<?php
/**
 * File:    vulnerable_app.php
 * Purpose: SAST fixture. PHP injection, file inclusion, deserialization, XSS,
 *          weak crypto and hardcoded credential defects.
 *          Intentionally vulnerable - never deploy or include.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 *
 * Expected CWEs: 89, 78, 95, 98, 502, 79, 22, 327, 798, 601, 918.
 */

// CWE-798: credentials in source
$dbHost = 'localhost';
$dbUser = 'root';
$dbPass = 'Pr0dPassw0rd!';
define('API_SECRET', 'php_hardcoded_api_secret_value');

$conn = new mysqli($dbHost, $dbUser, $dbPass, 'app');

// CWE-89: SQL injection
function findUser($conn, $email) {
    $sql = "SELECT id, email FROM users WHERE email = '" . $email . "'";
    return $conn->query($sql);
}

function findOrder($conn) {
    return mysqli_query($conn, "SELECT * FROM orders WHERE id = {$_GET['id']}");
}

// CWE-78: command injection
function ping() {
    system('ping -c 1 ' . $_GET['host']);
    shell_exec('nslookup ' . $_REQUEST['domain']);
    passthru('whois ' . $_POST['target']);
    exec('tar -czf /tmp/out.tgz ' . $_GET['dir']);
}

// CWE-95: dynamic evaluation
function evaluate() {
    eval($_POST['code']);
    $fn = create_function('$x', $_GET['body']);
    return $fn(1);
}

function callDynamic() {
    $callback = $_GET['fn'];
    return $callback($_GET['arg']);
}

// CWE-98: remote/local file inclusion
function loadModule() {
    include($_GET['page']);
    require_once($_GET['template'] . '.php');
}

// CWE-502: object injection
function loadSession() {
    return unserialize($_COOKIE['session']);
}

// CWE-79: reflected XSS
function greet() {
    echo "<h1>Hello " . $_GET['name'] . "</h1>";
    print($_REQUEST['message']);
}

// CWE-22: path traversal
function download() {
    readfile('/srv/files/' . $_GET['file']);
    echo file_get_contents($_GET['path']);
}

// CWE-918: SSRF
function proxy() {
    $ch = curl_init($_GET['url']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    return curl_exec($ch);
}

// CWE-327: broken hashing
function hashPassword($password) {
    return md5($password);
}

function legacyHash($data) {
    return sha1($data);
}

// CWE-601: open redirect
function go() {
    header('Location: ' . $_GET['next']);
}

// CWE-434: unrestricted upload
function upload() {
    move_uploaded_file($_FILES['f']['tmp_name'], '/var/www/html/' . $_FILES['f']['name']);
}
