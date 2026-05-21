plugins {
    `java-gradle-plugin`
    `maven-publish`
    kotlin("jvm") version "2.3.20"
    id("com.gradle.plugin-publish") version "1.3.1"
}

group = "io.github.mgerhardy"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(gradleApi())
    testImplementation("org.jetbrains.kotlin:kotlin-test")
}

testing {
    suites {
        val functionalTest by registering(JvmTestSuite::class) {
            useKotlinTest()
            dependencies {
                implementation(project())
            }
            gradlePlugin.testSourceSets.add(sources)
        }
    }
}

tasks.check { dependsOn(testing.suites.named("functionalTest")) }

gradlePlugin {
    website = "https://github.com/mgerhardy/gradle-trivy"
    vcsUrl = "https://github.com/mgerhardy/gradle-trivy"
    plugins {
        create("trivy") {
            id = "io.github.mgerhardy.trivy"
            implementationClass = "io.github.mgerhardy.trivy.TrivyPlugin"
            displayName = "Gradle Trivy Plugin"
            description = "Generates lock files for npm/Java builds and auto-downloads Trivy for vulnerability scanning"
            tags = listOf("security", "trivy", "vulnerability", "scanning", "npm", "lockfile")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
