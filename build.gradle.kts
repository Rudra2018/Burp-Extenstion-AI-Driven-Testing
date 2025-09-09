plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.secure.ai"
version = "2.0.0"

repositories {
    mavenCentral()
    maven {
        name = "PortSwigger"
        url = uri("https://releases.portswigger.net/maven/")
    }
}

dependencies {
    // Essential libraries for demonstration
    implementation("com.fasterxml.jackson.core:jackson-core:2.15.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.2")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2")
    implementation("com.squareup.okhttp3:okhttp:4.11.0")
    implementation("org.apache.commons:commons-math3:3.6.1")
    implementation("org.apache.commons:commons-text:1.10.0")
    implementation("org.jsoup:jsoup:1.16.1")
    implementation("org.apache.commons:commons-exec:1.3")
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")
    implementation("org.slf4j:slf4j-api:2.0.7")
    implementation("ch.qos.logback:logback-classic:1.4.8")
    implementation("com.typesafe:config:1.4.2")
}

// Create the extension JAR
tasks.shadowJar {
    archiveFileName.set("ai-security-extension-${version}.jar")
    manifest {
        attributes["Main-Class"] = "com.secure.ai.burp.AISecurityExtension"
    }
    
    // Exclude conflicting files
    exclude("META-INF/*.SF")
    exclude("META-INF/*.DSA") 
    exclude("META-INF/*.RSA")
    
    // Merge service files
    mergeServiceFiles()
}

// Configure Java compilation
java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

tasks.compileJava {
    options.encoding = "UTF-8"
}

// Configure jar task to include the main class
tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.secure.ai.burp.AISecurityExtension"
    }
}

tasks.test {
    useJUnitPlatform()
}