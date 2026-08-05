pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Tesseract4Android is not published to Maven Central, only here. JitPack builds
        // artifacts from a git tag on demand rather than serving a release the author
        // uploaded, so it is a weaker guarantee than the two above and is deliberately
        // narrowed to the one group that needs it.
        //
        // If that is not good enough, the project can be built from source and installed
        // with its own publishToMavenLocal task, and mavenLocal() used instead.
        maven {
            url = uri("https://jitpack.io")
            content { includeGroup("cz.adaptech.tesseract4android") }
        }
    }
}

rootProject.name = "passauf"
include(":app")
