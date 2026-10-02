//! The transport, driven the way the app drives it: with no runtime of its own.
//!
//! Every other request this crate makes in a test runs inside `#[tokio::test]`,
//! which is not where the app is. The share loop calls `block_on` on a plain
//! thread, and a future that needs a reactor cannot be completed by polling it
//! in a loop — it panics, and under `panic = "abort"` a panic is not an error
//! report, it is the process closing. So the one test that has to be ordinary
//! is this one: a socket, a request, and no runtime in sight.

use std::io::{Read, Write};

use kestrel_net::Relay;

/// A one-request HTTP server on a random port, on this thread's terms.
///
/// Deliberately not the test relay: this test is about the client's
/// environment, and a server running inside a tokio runtime would answer the
/// question it is not asking.
fn serve_once(body: &str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let addr = listener.local_addr().expect("an address to answer on");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut head = [0u8; 2048];
        let _ = stream.read(&mut head);
        let _ = stream.write_all(response.as_bytes());
    });
    format!("http://{addr}")
}

#[test]
fn a_request_works_with_no_runtime_in_sight() {
    let base = serve_once(r#"{"now":1700000000000,"protocol":"v2"}"#);
    let mut relay = Relay::new(&base).expect("a local relay is a relay");

    // No `#[tokio::test]`, no `Runtime`, no waker: the same call the share loop
    // makes on its own thread, from a test thread.
    let body = kestrel_net::block_on(relay.health()).expect("the request came back");

    assert_eq!(kestrel_net::health_protocol(&body).as_deref(), Some("v2"));
    assert_eq!(kestrel_net::health_now(&body), Some(1_700_000_000_000));
}
