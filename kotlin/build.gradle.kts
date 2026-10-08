// The Secure AI client for Android and the JVM.
//
// One dependency, kotlinx-coroutines, which every Android app already has:
// the client's calls are suspend functions and its streamed answers a Flow.
// JSON and HTTP use what the platform ships, so it never brings a second
// copy of a library the app already chose a version of.
plugins {
    kotlin("jvm") version "2.0.21"
    `java-library`
    `maven-publish`
}

group = (findProperty("publishGroup") as String?) ?: "one.secureai"
version = (findProperty("publishVersion") as String?) ?: "0.1.0"

repositories { mavenCentral() }

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    testImplementation("junit:junit:4.13.2")
}

publishing {
    publications {
        create<MavenPublication>("release") {
            // JitPack builds from a tag and names it com.github.secureaione-jpg:secure-ai-sdk.
            artifactId = (findProperty("artifactName") as String?) ?: "secure-ai"
            from(components["java"])
            pom {
                name.set("Secure AI")
                description.set("Private AI chat and guarded agent actions for Android and the JVM.")
                url.set("https://secureai.one/developers")
                licenses { license { name.set("MIT") } }
            }
        }
    }
}
