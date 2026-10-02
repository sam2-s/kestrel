# Rules for R8 on the release build.
#
# The whole app is one web page talking to one Kotlin object: the page calls
# every bridge method by name off globalThis.KestrelNative, so a rename or a
# drop would not fail the build, it would fail silently at runtime on the
# first camera token, the first health snapshot, the first notice. Keep the
# annotated methods and their names; shrinking everything around them is
# still fine.
#
# This keep also lives in the stock proguard-android-optimize.txt; it is
# written out here because the entire app breaks if a future AGP ever stops
# carrying it, and the cost of saying it twice is nothing.
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Everything else the release build needs is pinned elsewhere already: classes
# named in the manifest (activities, services, receivers) are kept by R8 on
# its own, the AndroidX libraries ship their own consumer rules, and the only
# reflective calls in the wrapper are getSystemService(Class), which never
# sees a name R8 could rewrite.
