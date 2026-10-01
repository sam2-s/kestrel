use kestrel_core::{beacon, msg, seal, wire};
fn main() {
    let mut b = beacon::Beacon::new();
    let link = b.add(wire::TTL_MS, 1_000);
    let parsed = beacon::parse_fragment(&link.fragment()).unwrap();
    println!("channel eq: {}", parsed.channel() == link.channel());
    let body = serde_json::to_string(&msg::CircleMsg::loc(
        2_000,
        msg::Who::default(),
        msg::Fix::new(44.98, -93.27, 5.0),
    ))
    .unwrap();
    println!("body: {body}");
    let posts = b.posts(&body, wire::epoch_at(2_000), 2_000);
    println!("posts: {}", posts.len());
    let p = &posts[0];
    println!("m matches owner: {}", p.m == parsed.owner);
    let opened = seal::verify_and_open(p, &parsed.channel(), &parsed.key(), 2_000);
    println!("opened: {:?}", opened.is_some());
    println!("shape: {:?}", p.validate_shape());
    println!("keys match: {}", p.keys_match_claimed_id());
    println!("viewer: {:?}", beacon::verify_for_viewer(p, &parsed, 2_000).is_some());
}
