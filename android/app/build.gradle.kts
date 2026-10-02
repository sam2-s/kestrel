plugins {
    // AGP 9 ships built-in Kotlin support; no separate Kotlin plugin wanted.
    id("com.android.application") version "9.3.0"
}

android {
    namespace = "app.kestrel.map"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.kestrel.map"
        minSdk = 28
        targetSdk = 36
        versionCode = 2
        versionName = "0.1.0-alpha.1"
    }

    signingConfigs {
        // The same checked-in test key the Rust alpha under app.kestrel.map
        // was signed with, so this app upgrades over it instead of failing on
        // a signature mismatch. Not a release key: shipping one would mean
        // shipping everyone's key, and the update path is unforgiving about
        // that. A real release takes its key from the environment.
        create("testkey") {
            storeFile = rootProject.file("testkey.jks")
            storePassword = "kestrel"
            keyAlias = "kestrel"
            keyPassword = "kestrel"
        }
    }

    buildTypes {
        release {
            // R8 is on now (it was off upstream for the F-Droid flow, which
            // needed the bytes to match an independent rebuild); the keep
            // rules that matter for a WebView app live in proguard-rules.pro.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            vcsInfo.include = false
            signingConfig = signingConfigs.getByName("testkey")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}


dependencyLocking {
    lockAllConfigurations()
}

// The web app IS the app. Every build syncs ../../app into assets so the
// wrapper can never drift from what starlingmap.app serves. What stays out of
// the APK is everything a WebView can never ask for: sw.js (no service worker
// interception here, the assets are already local), _headers (server config),
// the Leaflet source map (only devtools read it), the social and PWA artwork
// (og/social cards and install icons are for browsers and stores), and
// robots/sitemap (crawlers of the hosted site). All of them stay in the repo
// for the site that serves app/.
val syncWebAssets = tasks.register<Sync>("syncWebAssets") {
    val webDir = rootProject.layout.projectDirectory.dir("../app")
    doFirst {
        val leaflet = webDir.file("vendor/leaflet/leaflet.js").asFile
        check(leaflet.isFile) {
            "app/vendor/leaflet is missing. Run: npm ci && bash tools/sync-vendor.sh (from the repo root)"
        }
    }
    from(webDir) {
        exclude(
            "sw.js",
            "_headers",
            "vendor/leaflet/leaflet-src.js.map",
            "icons/og.png",
            "icons/icon-192.png",
            "icons/icon-512.png",
            "icons/icon-maskable-512.png",
            "icons/apple-touch-icon.png",
            "robots.txt",
            "sitemap.xml",
        )
    }
    into(layout.buildDirectory.dir("webassets"))
}

android.sourceSets["main"].assets.srcDir(layout.buildDirectory.dir("webassets").get().asFile)

tasks.named("preBuild") {
    dependsOn(syncWebAssets)
}

dependencies {
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-ktx:1.11.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("info.guardianproject.panic:panic:1.0")
}
