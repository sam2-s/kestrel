//! The boundary contract, in one table.
//!
//! Every crossing between Rust and Java is listed here: the methods Java calls into
//! Rust, and the ones Rust calls into Java. Nothing crosses that is not on this list.
//!
//! It lives outside the Android module on purpose. The names here are the one thing
//! that has to agree across a language boundary, where a mismatch is not a compile
//! error but a crash or a silent no-op on a user's phone. Keeping the table in a
//! module the host can read means the test at the bottom can check it against the
//! actual Java source, which is the only way to catch a rename on either side.
//!
//! The check is real rather than a comment. It reads `Bridge.java` out of the
//! repository and fails if a declared `native` method has no Rust export, or if a Rust
//! export has no Java declaration. Renaming a method on one side without the other is
//! then a failing test rather than a `NoSuchMethodError`.

/// A method Java calls into Rust.
///
/// The name is the JNI export name: `Java_` + the binary class name with `/` and `_`
/// escaped, + the method. JNI's escaping rule is that only `/` becomes `_`, so a Java
/// class named `Bridge` in package `app.kestrel.map` is `app_kestrel_map_Bridge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntoRust {
    /// The Java method name.
    pub java: &'static str,
    /// The Java parameter types, written the way Java writes them.
    pub params: &'static str,
    /// The Rust `#[no_mangle]` export.
    pub export: &'static str,
}

/// A method Rust calls into Java, through [`crate::android::Android`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntoJava {
    /// The Java method name.
    pub java: &'static str,
    /// The JNI signature, used for the method lookup.
    pub signature: &'static str,
    /// How many arguments the app passes.
    pub arity: usize,
}

/// Everything Java calls into Rust.
///
/// The `report*` names are the whole of the Java-to-Rust direction: the service
/// reporting a fix, the platform reporting a permission, the scanner reporting a code,
/// and the activity reporting the back gesture. Four methods rather than one per
/// permission, because a permission arriving on its own method means a new permission
/// needs a symbol, a signature and a branch in three places.
pub const INTO_RUST: &[IntoRust] = &[
    IntoRust {
        java: "reportPermission",
        params: "String,String",
        export: "Java_app_kestrel_map_Bridge_reportPermission",
    },
    IntoRust {
        java: "reportLocation",
        params: "int,int,int,long,int",
        export: "Java_app_kestrel_map_Bridge_reportLocation",
    },
    IntoRust {
        java: "reportScan",
        params: "String",
        export: "Java_app_kestrel_map_Bridge_reportScan",
    },
    IntoRust {
        java: "reportBackground",
        params: "boolean",
        export: "Java_app_kestrel_map_Bridge_reportBackground",
    },
    IntoRust {
        java: "onBackPressedNative",
        params: "",
        export: "Java_app_kestrel_map_Bridge_onBackPressedNative",
    },
];

/// Everything Rust calls into Java.
pub const INTO_JAVA: &[IntoJava] = &[
    IntoJava { java: "requestLocation", signature: "requestLocation()V", arity: 0 },
    IntoJava {
        java: "requestBackgroundLocation",
        signature: "requestBackgroundLocation()V",
        arity: 0,
    },
    IntoJava {
        java: "requestNotifications",
        signature: "requestNotifications()V",
        arity: 0,
    },
    IntoJava { java: "requestCamera", signature: "requestCamera()V", arity: 0 },
    IntoJava { java: "openAppSettings", signature: "openAppSettings()V", arity: 0 },
    IntoJava {
        java: "openLocationSettings",
        signature: "openLocationSettings()V",
        arity: 0,
    },
    IntoJava { java: "startSharing", signature: "startSharing()V", arity: 0 },
    IntoJava { java: "stopSharing", signature: "stopSharing()V", arity: 0 },
    IntoJava { java: "startScan", signature: "startScan()V", arity: 0 },
    IntoJava {
        java: "notify",
        signature: "notify(Ljava/lang/String;Ljava/lang/String;)V",
        arity: 2,
    },
    IntoJava { java: "setProxy", signature: "setProxy(Ljava/lang/String;)V", arity: 1 },
    IntoJava {
        // Called from Rust, not through the signature table: it returns a byte[] rather
        // than being void, and it is on the decoding path where the copy matters.
        java: "nextFrame",
        signature: "nextFrame()[B",
        arity: 0,
    },
    // Asks Java for one more preview frame. Without this the queue is never filled and
    // the scanner sits waiting on a camera that has been told to hold its frames.
    IntoJava { java: "wantFrame", signature: "wantFrame()V", arity: 0 },
];

/// The JNI signature of a method in `INTO_JAVA`.
///
/// Read out of the table rather than passed in, so a caller cannot pair a method name
/// with the signature of a different one — which is precisely the mistake this table
/// exists to prevent.
pub fn signature_of(java: &str) -> Option<&'static str> {
    INTO_JAVA.iter().find(|m| m.java == java).map(|m| m.signature)
}

/// How many arguments a method in `INTO_JAVA` takes.
pub fn arity_of(java: &str) -> Option<usize> {
    INTO_JAVA.iter().find(|m| m.java == java).map(|m| m.arity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Java source this table has to agree with.
    ///
    /// Located from the crate root rather than the working directory, so the test finds
    /// it whether cargo was run from the workspace or from inside the crate.
    fn bridge_java() -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../android/app/src/main/java/app/kestrel/map/Bridge.java");
        std::fs::read_to_string(path).ok()
    }

    /// The Rust source the exports are declared in.
    fn android_rs() -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/android.rs");
        std::fs::read_to_string(path).ok()
    }

    /// Every method Java declares `native`, with its parameters.
    ///
    /// A small scan rather than a parser: it looks for the word `native` and takes the
    /// declaration that follows. Crude, but a false positive needs a hand-written
    /// comment reading "static native void onBackPressedNative()" in a row, and a false
    /// negative needs someone to remove a `native` keyword from a real method — which is
    /// the change this is meant to catch.
    fn declared_natives(java: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        for line in java.lines() {
            // Modifiers first: a native method may be private, and dropping everything
            // before `static` would make a private one invisible, which is exactly the
            // kind of method most likely to be renamed alone.
            let line = line.trim();
            let Some(rest) = line
                .strip_prefix("private ")
                .or_else(|| line.strip_prefix("public "))
                .or_else(|| line.strip_prefix("protected "))
                .unwrap_or(line)
                .strip_prefix("static ")
                .unwrap_or(line)
                .strip_prefix("native ")
            else {
                continue;
            };
            let Some(paren) = rest.find('(') else { continue };
            let Some(close) = rest.find(')') else { continue };
            let params = rest[paren + 1..close].to_string();
            // The name sits between the return type and the opening paren.
            let head = rest[..paren].trim();
            let name = head
                .rsplit(|c: char| c.is_whitespace() || c == '<' || c == '>')
                .next()
                .unwrap_or("");
            // The table records types, not the names Java gives them; `String which` and
            // `String` are the same signature and the name changes freely.
            let types = params
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                // First word, not last: `String which` is the type then the name, so the
                // last word is the name.
                .map(|p| p.split_whitespace().next().unwrap_or(p).to_string())
                .collect::<Vec<_>>()
                .join(",");
            found.push((name.to_string(), types));
        }
        found
    }

    #[test]
    fn every_native_method_java_declares_has_a_rust_export() {
        let (Some(java), Some(rs)) = (bridge_java(), android_rs()) else {
            // The Java tree is not present, which happens if the crate is vendored on
            // its own. Nothing to check against, and nothing to pretend about.
            return;
        };
        let declared = declared_natives(&java);
        assert!(
            !declared.is_empty(),
            "found no native methods in Bridge.java, so the scan is broken rather than the code being empty"
        );
        for (name, _) in &declared {
            let entry = INTO_RUST.iter().find(|m| m.java == name).unwrap_or_else(|| {
                panic!("Java declares native {name} but the table does not list it")
            });
            assert!(
                rs.contains(entry.export),
                "{} is declared in Java and listed, but there is no such export in android.rs",
                entry.java
            );
        }
    }

    #[test]
    fn every_rust_export_has_a_java_declaration() {
        let (Some(java), Some(rs)) = (bridge_java(), android_rs()) else {
            return;
        };
        let declared = declared_natives(&java);
        for entry in INTO_RUST {
            assert!(
                declared.iter().any(|(n, _)| n == entry.java),
                "{} is listed and exported, but Java does not declare it native",
                entry.java
            );
        }
        // And nothing extra is exported behind the table's back.
        for export in rs
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub extern \"system\" fn "))
            .map(|l| l.split(['<', '(']).next().unwrap_or("").trim())
            .filter(|n| n.starts_with("Java_"))
        {
            assert!(
                INTO_RUST.iter().any(|m| m.export == export),
                "{export} is exported but is not in the table"
            );
        }
    }

    #[test]
    fn the_table_records_the_parameters_java_actually_uses() {
        let Some(java) = bridge_java() else { return };
        let declared = declared_natives(&java);
        for entry in INTO_RUST {
            let Some((_, params)) = declared.iter().find(|(n, _)| n == entry.java) else {
                continue;
            };
            assert_eq!(
                params, entry.params,
                "{} takes different parameters in Java than the table says",
                entry.java
            );
        }
    }

    /// How many arguments a signature takes, counted from the signature itself.
    ///
    /// Only used on the host, where the jni crate is not a dependency. The real call
    /// parses the signature with the jni crate and checks the count there; this is the
    /// same rule written out, so a typo in the table is still caught by a host test
    /// rather than waiting for an Android build.
    fn count_args(sig: &str) -> Option<usize> {
        let open = sig.find('(')?;
        let close = sig.find(')')?;
        if close < open {
            return None;
        }
        let params = &sig[open + 1..close];
        if params.is_empty() {
            return Some(0);
        }
        // Each parameter ends with a semicolon, so splitting leaves a trailing empty
        // piece. Dropped rather than skipped: "a;b;" is two parameters, not three.
        Some(params.split(';').filter(|p| !p.is_empty()).count())
    }

    #[test]
    fn every_signature_takes_the_number_of_arguments_the_table_claims() {
        for entry in INTO_JAVA {
            assert_eq!(
                count_args(entry.signature),
                Some(entry.arity),
                "{} is called with {} arguments, but its signature says otherwise",
                entry.java,
                entry.arity
            );
        }
    }

    #[test]
    fn every_signature_names_the_method_it_belongs_to() {
        // `()V` is a valid signature for any method, so a name that does not match is
        // the failure this catches.
        for entry in INTO_JAVA {
            assert!(
                entry.signature.starts_with(&format!("{}(", entry.java)),
                "{} has the signature {}",
                entry.java,
                entry.signature
            );
            // Everything after the closing paren is the return type. Empty would mean a
            // void return with nothing named, which no Java method has.
            let close = entry.signature.rfind(')').unwrap_or(0);
            assert!(
                !entry.signature[close + 1..].trim().is_empty(),
                "{} declares no return type",
                entry.java
            );
        }
    }

    #[test]
    fn a_method_with_no_entry_has_no_signature() {
        assert!(signature_of("somethingNobodyCalls").is_none());
        assert_eq!(arity_of("somethingNobodyCalls"), None);
        assert_eq!(signature_of("setProxy"), Some("setProxy(Ljava/lang/String;)V"));
        assert_eq!(arity_of("setProxy"), Some(1));
    }

    #[test]
    fn the_table_has_no_duplicates() {
        // A duplicate would let one entry shadow another, and the shadowed one would be
        // a method nobody tests.
        let mut names: Vec<&str> = INTO_RUST.iter().map(|m| m.java).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "INTO_RUST has a duplicate");
        let mut names: Vec<&str> = INTO_JAVA.iter().map(|m| m.java).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "INTO_JAVA has a duplicate");
    }
}
