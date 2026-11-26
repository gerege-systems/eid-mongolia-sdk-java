// eID Mongolia client-side PAdES — plain Java 17 (JVM, server-side), byte-identical to the Go reference
// (gerege-systems/eid-mongolia-sdk-go `pades`, profile pades-client/1). Zero runtime dependencies — java.security +
// a minimal DER writer. Conformance: src/test/resources/golden (scripts/sync-pades-golden.sh), run in CI only.
plugins {
    `java-library`
    `maven-publish`
}

group = "com.github.gerege-systems"
// JitPack sets VERSION to the git tag; the release workflow does the same. Without it: the version being prepared.
version = System.getenv("VERSION") ?: "0.3.0"

java {
    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(17)
    options.compilerArgs.addAll(listOf("-Xlint:deprecation,unchecked"))
}

tasks.withType<Javadoc>().configureEach {
    options.encoding = "UTF-8"
    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
}

tasks.test {
    useJUnit()
    maxHeapSize = "1g"
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        // The live contract test (contract.yml) prints its WARN lines and ::warning annotations.
        showStandardStreams = System.getenv("EID_CONTRACT") == "1"
    }
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "eID Mongolia PAdES SDK (Java)",
            "Implementation-Version" to project.version,
            "Automatic-Module-Name" to "mn.eidmongolia.eid.pades",
        )
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "eid-mongolia-sdk-java"
            from(components["java"])
            pom {
                name.set("eID Mongolia PAdES SDK (Java)")
                description.set("eID Mongolia relying-party SDK: RP-API client, response validator, sign-in backend, client-side PAdES (pades-client/1) and «My QR» verification")
                url.set("https://github.com/gerege-systems/eid-mongolia-sdk-java")
                licenses { license { name.set("MIT"); url.set("https://opensource.org/licenses/MIT") } }
            }
        }
    }
}
