use kestrel_core::{
    identity::Identity,
    kdf, msg,
    roster::Roster,
    session::{Circle, Reject, me},
    wire,
};
fn at(e: i64) -> i64 {
    e * wire::EPOCH_MS
}
fn main() {
    let seed = [7u8; 32];
    let now = at(2980471);
    let a_id = Identity::generate();
    let mut a = Circle::create(a_id.clone(), &seed, now);
    let b_id = Identity::generate();
    let mut b = Circle::join(
        b_id.clone(),
        &seed,
        kdf::channel_id(&kdf::anchor(&seed)),
        0,
        wire::epoch_at(now),
        Roster::new(),
        now,
    );
    let post = b
        .location(
            &me(&b_id, "Bo", "", 0.8, msg::ShareMode::Precise),
            msg::Fix::new(44.98, -93.27, 5.0),
            msg::ShareMode::Precise,
            now + 1000,
        )
        .unwrap();
    println!("post e={} ts={} now={}", post.e, post.ts, now + 1000);
    println!("a channel {} b channel {}", a.channel(), b.channel());
    let before = a.roster().clone();
    match a.ingest(&post, &before, now + 1000) {
        Ok(ev) => println!("ok {ev:?}"),
        Err(e) => println!("reject {e:?}"),
    }
    println!(
        "members known: {:?}",
        a.members().iter().map(|m| m.member.member_id.clone()).collect::<Vec<_>>()
    );
    let _ = Reject::OwnPost;
}
