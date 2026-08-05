import com.android.build.api.artifact.SingleArtifact

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

    /**
     * Release signing, if this machine has the key.
     *
     * The keystore and its password live in ~/.gradle/gradle.properties, never in the
     * project. A signing key is the app's permanent identity: whoever holds it can
     * publish an update that every device already carrying passauf will accept as
     * genuine, and there is no revoking it for a sideloaded app. A properties file in
     * the project directory is one `git add -A` away from making that everyone's key.
     *
     * Absent the properties a release build still succeeds, unsigned, so a fresh clone
     * builds for anyone.
     */
    val keystore = (project.findProperty("passauf.storeFile") as String?)?.let(::file)
    if (keystore?.exists() == true) {
        signingConfigs {
            create("release") {
                storeFile = keystore
                storePassword = project.property("passauf.storePassword") as String
                keyAlias = project.property("passauf.keyAlias") as String
                keyPassword = project.property("passauf.keyPassword") as String

                // v1 is JAR signing, only needed below Android 7, and minSdk is 26.
                enableV1Signing = false
                enableV2Signing = true
                // v3 carries a signing certificate lineage, which is the only way to
                // ever rotate this key without every existing install refusing the
                // update as coming from someone else. It costs nothing now and cannot
                // be added retroactively to APKs already in the wild.
                enableV3Signing = true

                if (storePassword == "passauf") {
                    logger.warn(
                        "passauf: the release keystore is still on its placeholder " +
                            "password. Whoever holds this key can ship an update every " +
                            "existing install will accept. Change it before publishing."
                    )
                }
            }
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
            signingConfig = signingConfigs.findByName("release")
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
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.kotlinx.serialization.json)

    // Reading the MRZ off a document with the camera, so the three fields do not have
    // to be typed. Tesseract runs the OCR-B model in assets/tessdata, trained by the
    // scripts in tesseract-ocrb-passauf/. Neither library touches the network, and the
    // manifest makes sure of it rather than trusting them.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.tesseract4android)

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

/**
 * Permissions this app must never ship, whoever asks for them.
 *
 * Everything passauf claims about privacy rests on there being no way off the
 * device, and that is not something the app source can settle on its own: ML Kit
 * pulls in com.google.android.datatransport, which declares INTERNET and
 * ACCESS_NETWORK_STATE, and the manifest merger folds them in silently. They are
 * stripped in AndroidManifest.xml with tools:node="remove".
 *
 * A dependency bump could undo that without a word, so the build checks rather
 * than trusts.
 */
val forbiddenPermissions = listOf(
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
)

androidComponents {
    onVariants { variant ->
        val variantName = variant.name.replaceFirstChar { it.uppercase() }
        val mergedManifest = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)

        val verify = tasks.register("verify${variantName}CannotReachTheNetwork") {
            group = "verification"
            description = "Fails if anything merged a network permission into the manifest."

            inputs.file(mergedManifest)
            doLast {
                val manifest = mergedManifest.get().asFile.readText()
                val found = forbiddenPermissions.filter { manifest.contains(it) }
                if (found.isNotEmpty()) {
                    throw GradleException(
                        buildString {
                            appendLine("A network permission reached the merged manifest:")
                            found.forEach { appendLine("  $it") }
                            appendLine()
                            appendLine(
                                "passauf reads passports and says it cannot send them anywhere. " +
                                    "That has to stay true. Find who asked in"
                            )
                            appendLine("  app/build/outputs/logs/manifest-merger-*-report.txt")
                            append(
                                "and strip it in AndroidManifest.xml with tools:node=\"remove\", " +
                                    "or drop the dependency."
                            )
                        }
                    )
                }
            }
        }

        // onVariants runs before AGP has created the assemble tasks, so this waits for
        // the one it wants to show up rather than asking for it by name now.
        tasks.matching { it.name == "assemble$variantName" }.configureEach {
            dependsOn(verify)
        }
    }
}
