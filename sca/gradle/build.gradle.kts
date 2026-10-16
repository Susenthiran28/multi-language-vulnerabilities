// File:    build.gradle.kts
// Purpose: SCA fixture. Gradle Kotlin DSL manifest pinned to known-vulnerable releases.
//          Exercises the .kts parser branch separately from the Groovy DSL.
//          DO NOT BUILD OR DEPLOY.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16

plugins {
    java
}

group = "com.vigilnz.fixtures"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // CVE-2021-44228 Log4Shell
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")

    // CVE-2022-1471 SnakeYAML constructor RCE
    implementation("org.yaml:snakeyaml:1.30")

    // Deserialization gadget chains
    implementation("com.fasterxml.jackson.core:jackson-databind:2.9.8")

    // CVE-2022-42889 Text4Shell
    implementation("org.apache.commons:commons-text:1.9")

    // Known-vulnerable Netty range
    implementation("io.netty:netty-handler:4.1.68.Final")

    // Known-vulnerable OkHttp range
    implementation("com.squareup.okhttp3:okhttp:4.9.1")

    testImplementation("junit:junit:4.12")
}
