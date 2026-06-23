plugins {
    id("java")
    // Builds the single fat-jar Burp loads. (Successor to johnrengelman.shadow.)
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.burpmcp"
version = "0.1.1"

java {
    toolchain {
        // Burp 2023.x+ runs on Java 17/21. Montoya requires 17+.
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime -> compileOnly. Bump to the latest version you have.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.5")

    // Bundled into the fat jar (Burp does NOT provide these):
    implementation("org.xerial:sqlite-jdbc:3.47.1.0")
    implementation("com.google.code.gson:gson:2.11.0")
}

tasks.shadowJar {
    archiveBaseName.set("burp-logger-mcp")
    archiveClassifier.set("")
    archiveVersion.set(project.version.toString())
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
