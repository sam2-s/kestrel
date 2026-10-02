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

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Signed with the checked-in test key so `assembleRelease` produces something
            // installable. Not a release key: shipping one means shipping everyone's, and
            // the update path is unforgiving about that. A real release would take the key
            // from the environment and never commit it.
            signingConfig = signingConfigs.getByName("testkey")
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
                // Kotlin's stdlib builtins, which R8 keeps whether or not the app uses
                // Kotlin. There is no Kotlin in Kestrel; these are ~40 KB of nothing.
                "kotlin/**",
                "META-INF/*.kotlin_module",
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

}

// ---------------------------------------------------------------- the Rust build
//
// cargo-ndk is driven directly rather than through a CMake wrapper. CMake would add
// a configure step and a second description of the same target triples, and the only
// thing it would do here is copy one file.

val rustCrate = rootProject.file("../crates/kestrel-app")
// One directory per profile. Sharing one would make Gradle treat the debug build's
// output as satisfying the release task's, and ship an unstripped 94 MB library in the
// release APK — which is exactly what happened the first time.
val rustOutDebug = layout.buildDirectory.dir("rustJniLibs/debug")
val rustOutRelease = layout.buildDirectory.dir("rustJniLibs/release")
val rustTargetDir = rootProject.file("../target/android-build")

/** The one ABI this ships. A 32-bit build would add ~3 MB of the same code twice. */
val ABI = "arm64-v8a"

/**
 * One cargo build, as an `Exec` task.
 *
 * An `Exec` rather than a `doLast` that shells out: the configuration cache cannot
 * serialise a build script object, so a closure holding one fails the build. `Exec`
 * carries nothing but strings, which is exactly what a cargo invocation needs.
 */
fun cargoBuild(name: String, release: Boolean) =
    tasks.register<Exec>(name) {
        description = "Compiles the Rust app for arm64, " +
            (if (release) "stripped." else "unoptimised.")
        // cargo-ndk already appends the ABI directory itself, so this is a jniLibs root
        // and nothing more. Adding the ABI here nests it twice and AGP then finds no .so
        // where it expects one — a 29 KB APK with no library in it.
        val out = if (release) rustOutRelease else rustOutDebug
        val outDir = out.get().asFile
        val manifest = rustCrate.resolve("Cargo.toml").absolutePath
        val workDir = rustCrate.parentFile.parentFile
        val profile = if (release) "release" else "debug"
        workingDir = workDir
        // cargo-ndk takes its own options first, then everything after is passed to
        // cargo — so the subcommand and --release have to come last or cargo rejects them
        // as unknown arguments to itself. The platform matches minSdk, so the library is
        // not built against a lower API than the app declares.
        commandLine(
            listOf(
                "cargo", "ndk",
                "-t", ABI,
                "-P", "26",
                "-o", outDir.absolutePath,
                "--manifest-path", manifest,
                "build",
                *(if (release) arrayOf("--release") else emptyArray()),
                "--target-dir", rustTargetDir.absolutePath,
            ),
        )
        // Declared up front so a source edit re-runs this and a comment edit does not.
        inputs.file(manifest)
        inputs.dir(rustCrate.resolve("src")).withPathSensitivity(PathSensitivity.RELATIVE)
        outputs.dir(out)
    }

val buildRustDebug = cargoBuild("buildRustDebug", release = false)
val buildRustRelease = cargoBuild("buildRustRelease", release = true)

// Each variant gets the output of the matching cargo build, and nothing else. Putting
// both on the source set looks harmless and is not: AGP sees the same
// `lib/arm64-v8a/libkestrel_app.so` twice and fails on duplicate resources — or worse,
// picks the debug one and ships an unstripped 94 MB library.
androidComponents {
    onVariants { variant ->
        val isRelease = variant.buildType == "release"
        val dir = (if (isRelease) rustOutRelease else rustOutDebug).get().asFile.absolutePath
        variant.sources.jniLibs?.addStaticSourceDirectory(dir)
    }
}

// Only the merge needs the library to exist, so an unrelated resource task does not
// trigger a five-minute Rust compile. Registered outside `onVariants`: registering it
// per variant makes every merge depend on every build, so assembling a release compiles
// the debug library too.
//
// The task name is `mergeReleaseJniLibFolders` with a lowercase `merge`, which is why
// this checked for "Merge" and never matched — and why an edited crate shipped a day-old
// .so, because cargo was never asked to rebuild it.
tasks.configureEach {
    if (name.contains("merge") && name.contains("JniLibFolders")) {
        val build = if (name.contains("Release")) buildRustRelease else buildRustDebug
        dependsOn(build)
    }
}

