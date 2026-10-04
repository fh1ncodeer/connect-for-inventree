fn main() {
    // A baked-in gateway id must be valid, otherwise the app could never connect.
    println!("cargo:rerun-if-env-changed=INVENTREE_GATEWAY_ID");
    if let Ok(id) = std::env::var("INVENTREE_GATEWAY_ID") {
        assert!(
            id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()),
            "INVENTREE_GATEWAY_ID must be the 64 character hex id printed by `inventree-gw id`"
        );
    }
    tauri_build::build()
}
