plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

val rustAbis: List<String> = (project.findProperty("passauf.rustAbis") as String? ?: "arm64-v8a")
    .split(",")
    .map { it.trim() }
    .filter { it.isNotEmpty() }
val skipRustBuild = (project.findProperty("passauf.skipRustBuild") as String?).toBoolean()

android {
    namespace = "zone.ave.passauf"
    compileSdk = 36

    defaultConfig {
        applicationId = "zone.ave.passauf"
        // Matches API_LEVEL in build-rust.sh, which is what the NDK stamps into
        // libpassauf.so. Raising one without the other gives a library the
        // device refuses to load.
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters.addAll(rustAbis)
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            // The .so has to stay a real file on disk for System.loadLibrary to
            // find it on older releases; extracting is the safe default.
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.serialization.json)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.kotlin.test)
}

/**
 * Cross-compile the Rust library into src/main/jniLibs before anything is
 * packaged. Without this, a clean checkout builds an APK with no native library
 * in it, which only fails once you run it.
 */
val buildRust by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compiles the passauf Rust library for the configured ABIs."

    val script = rootProject.file("build-rust.sh")
    val crateRoot = rootProject.file("..")

    // Rebuilding takes long enough to be worth skipping when nothing changed.
    inputs.file(crateRoot.resolve("Cargo.toml"))
    inputs.dir(crateRoot.resolve("src"))
    inputs.property("abis", rustAbis)
    outputs.dir(layout.projectDirectory.dir("src/main/jniLibs"))

    commandLine(listOf(script.absolutePath) + rustAbis)
    // Cargo's own output is the useful part when this fails.
    isIgnoreExitValue = false

    onlyIf {
        if (skipRustBuild) {
            logger.lifecycle("Skipping the Rust build (passauf.skipRustBuild is set).")
        }
        !skipRustBuild
    }
}

tasks.named("preBuild") {
    dependsOn(buildRust)
}
