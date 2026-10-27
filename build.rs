fn main() {
    // Android gets the phone layout; `CIPHER_UI=phone` previews it on a desktop.
    println!("cargo::rerun-if-env-changed=CIPHER_UI");
    println!("cargo::rustc-check-cfg=cfg(phone_ui)");
    let phone = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android")
        || std::env::var("CIPHER_UI").as_deref() == Ok("phone");
    if phone {
        println!("cargo::rustc-cfg=phone_ui");
    }

    // The window is always dark, so the standard widgets must be too, whatever the OS theme.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    let window = if phone { "ui/phone-window.slint" } else { "ui/main-window.slint" };
    slint_build::compile_with_config(window, config).expect("Slint build failed");

    // TUN needs admin rights on Windows: embed a manifest that asks for elevation.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("windows/app.rc", embed_resource::NONE)
            .manifest_required()
            .expect("failed to embed the Windows manifest");
    }
}
