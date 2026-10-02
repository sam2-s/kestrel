# Kestrel's shrinker rules.
#
# R8 cannot see that the `native` methods in Bridge.java are called: they are looked up
# by name at runtime, through JNI, from Rust. Without these rules it strips them, the
# app builds, and then pressing any button throws UnsatisfiedLinkError on a phone.
#
# That is the same class of mistake as a wrong method signature, and it fails the same
# way — at the moment a person uses the app.

# The bridge class and everything native in it.
-keepclasseswithmembernames,includedescriptorclasses class app.kestrel.map.Bridge {
    native <methods>;
}

# Belt and braces: keep the class itself even if the member rule above is ever
# narrowed. The class is the entire Java-to-Rust direction of the boundary.
-keep class app.kestrel.map.Bridge { *; }

# Every other class in the app is referenced from the manifest, and the manifest is not
# visible to the shrinker either. Without this, MainActivity's lifecycle methods go and
# the app starts with no activity.
-keep class app.kestrel.map.MainActivity { *; }
-keep class app.kestrel.map.ScanActivity { *; }
-keep class app.kestrel.map.ShareService { *; }
-keep class app.kestrel.map.BootReceiver { *; }
-keep class app.kestrel.map.ShareService$StopReceiver { *; }

# The camera is used through reflection by the framework's Camera class, and its
# PreviewCallback is an interface the framework calls.
-keep class * implements android.hardware.Camera$PreviewCallback { *; }
-keepclassmembers class * implements android.hardware.Camera$PreviewCallback {
    void onPreviewFrame(byte[], android.hardware.Camera);
}

# NativeActivity loads the library and then calls the native entry point, which it
# finds by name.
-keep class android.app.NativeActivity { *; }

# Line numbers make a release crash report readable. The file name and the source file
# name stay too; the cost is a few kilobytes and the benefit is a stack trace someone
# can act on.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Kotlin's metadata is not used: there is no Kotlin in this app. Left off so the
# annotation is not carried for nothing.
-dontnote kotlin.**