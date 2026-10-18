fn main() {
    // The window is always dark, so the standard widgets must be too, whatever the OS theme.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/main-window.slint", config).expect("Slint build failed");

    // TUN needs admin rights on Windows: embed a manifest that asks for elevation.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("windows/app.rc", embed_resource::NONE)
            .manifest_required()
            .expect("failed to embed the Windows manifest");
    }
}
