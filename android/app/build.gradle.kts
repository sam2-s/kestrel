import java.util.Properties

plugins {
    id("com.android.application")
}

// Where the NDK is. Normally ANDROID_NDK_HOME or ANDROID_HOME is enough, but the
// NDK that cargo-ndk uses must be the same one AGP uses, or the C runtime and the
// Rust binary disagree about which libc they link. An explicit key wins.
val ndkVersion: String = run {
    val local = Properties().apply {
        val f = rootProject.file("local.properties")
        if (f.exists()) f.inputStream().use { load(it) }
    }
    local.getProperty("ndkVersion") ?: "27.1.12297006"
}

android {
    namespace = "app.kestrel.map"
    ndkVersion = ndkVersion
    compileSdk = 36

    defaultConfig {
        applicationId = "app.kestrel.map"
        // 26 is the floor: below that, foreground service types and the permission
        // model this app relies on do not exist, and the older model is worse for
        // the user than not shipping at all.
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        // arm64 only. A 32-bit build would double the ABI list and add roughly 3 MB
        // of a second copy of the same code, for devices that cannot run a current
        // Android anyway.
        ndk {
            abiFilters += listOf("arm64-v8a")
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
        debug {
            // The Rust library is built the same way in both, so a debug build tests
            // the same binary that a release build ships.
            isMinifyEnabled = false
        }
    }

    // No AndroidX and no Kotlin: the shim is four small Java files and the app is
    // Rust, so a support library would be a megabyte of code that is never called.
    buildFeatures {
        buildConfig = false
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/DEPENDENCIES",
                "/META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            )
        }
        // The Rust library is already stripped by the release profile.
        jniLibs {
            useLegacyPackaging = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        // A debug key so `assembleRelease` produces something installable for
        // testing. Not a release key: shipping one would mean shipping everyone's
        // key, and the update path is unforgiving about that.
        create("testkey") {
            storeFile = rootProject.file("testkey.jks")
            storePassword = "kestrel"
            keyAlias = "kestrel"
            keyPassword = "kestrel"
        }
    }
}

// ---------------------------------------------------------------- the Rust build
//
// cargo-ndk is driven directly rather than through a CMake wrapper. CMake would add
// a configure step and a second description of the same target triples, and the only
// thing it would do here is copy one file.

val rustCrate = rootProject.file("../crates/kestrel-app")
val rustOut = layout.buildDirectory.dir("rustJniLibs")
val rustTargetDir = rootProject.file("../target/android-build")

/** The arm64 triple name for an ABI. One ABI, because one is all this ships. */
fun tripleFor(abi: String): String =
    when (abi) {
        "arm64-v8a" -> "aarch64-linux-android"
        else -> error("Kestrel does not build for $abi; see abiFilters")
    }

fun cargoBuild(abi: String, release: Boolean) {
    val profile = if (release) "release" else "debug"
    val out = rustOut.get().asFile.resolve(abi)
    out.mkdirs()
    providers.exec {
        workingDir = rustCrate.parentFile.parentFile
        commandLine(
            listOf(
                "cargo", "ndk",
                "-t", abi,
                "-o", out.absolutePath,
                *(if (release) arrayOf("--release") else arrayOf("--debug")),
                "--target-dir", rustTargetDir.absolutePath,
                "--manifest-path", rustCrate.resolve("Cargo.toml").absolutePath,
            ),
        )
    }.result.get().let { result ->
        // A failed cargo build must fail the Gradle build. Left unchecked, the missing
        // .so would not show up until an install on a real phone.
        if (result.exitValue != 0) {
            throw GradleException("cargo ndk build failed (exit ${result.exitValue})")
        }
    }
}

// Registered per build type rather than once, because the release flag changes what
// cargo is asked for and a single task cannot have two meanings.
val buildRustDebug = tasks.register("buildRustDebug") {
    description = "Compiles the Rust app for arm64, unoptimised."
    inputs.file(rustCrate.resolve("Cargo.toml"))
    inputs.dir(rustCrate.resolve("src"))
    outputs.dir(rustOut)
    doLast { cargoBuild("arm64-v8a", release = false) }
}

val buildRustRelease = tasks.register("buildRustRelease") {
    description = "Compiles the Rust app for arm64, stripped."
    inputs.file(rustCrate.resolve("Cargo.toml"))
    inputs.dir(rustCrate.resolve("src"))
    outputs.dir(rustOut)
    doLast { cargoBuild("arm64-v8a", release = true) }
}

// AGP's own native build is off: it has no CMakeLists to run, and enabling it would
// only add a step that fails.
android {
    sourceSets.getByName("main") {
        jniLibs.directories.add(rustOut.get().asFile.absolutePath)
    }
}

tasks.withType<com.android.build.gradle.tasks.MergeSourceSetFolders>().configureEach {
    // Only the merge needs the library to exist; leaving the rest undepended on keeps
    // lint and resource tasks fast.
    if (name.contains("JniLibFolders")) {
        dependsOn(buildRustDebug, buildRustRelease)
    }
}
