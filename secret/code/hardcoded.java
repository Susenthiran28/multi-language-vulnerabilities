/*
 * File:    hardcoded.java
 * Purpose: Secret-scanner fixture. Credentials embedded in Java source.
 *          All values are synthetic and non-functional.
 * Author:  Vigilnz Security Engineering
 * Date:    2026-10-16
 */

package com.vigilnz.fixtures;

public final class HardcodedSecrets {

    public static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    public static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    public static final String JDBC_URL = "jdbc:mysql://db.internal.example.com:3306/app?user=root&password=FixtureRootPass";
    public static final String API_KEY = "ak_live_java_0123456789abcdef";
    public static final String DB_PASSWORD = "Pr0dPassw0rd!";
    public static final String JWT_SECRET = "fixture-jwt-signing-secret-000000000000";
    public static final String STRIPE_SECRET = "sk_live_FIXTURE0000000000000000000000";

    private HardcodedSecrets() {
    }
}
