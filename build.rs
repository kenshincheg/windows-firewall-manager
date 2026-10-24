fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    // Windows Explorer and the UI use the same Cargo version.
    let version = std::env::var("CARGO_PKG_VERSION").expect("package version");
    let numbers = version.split('.').collect::<Vec<_>>().join(",");
    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let version_rc = out_dir.join("version.rc");
    std::fs::write(
        &version_rc,
        format!(
            r#"
1 VERSIONINFO
FILEVERSION {numbers},0
PRODUCTVERSION {numbers},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "FileDescription", "Windows Firewall Manager\0"
            VALUE "FileVersion", "{version}\0"
            VALUE "ProductName", "Windows Firewall Manager\0"
            VALUE "ProductVersion", "{version}\0"
            VALUE "OriginalFilename", "firewall_windows.exe\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#
        ),
    )
    .expect("write version resource");
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=icon.rc");
    println!("cargo:rerun-if-changed=assets/icon.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    embed_resource::compile(version_rc, embed_resource::NONE)
        .manifest_optional()
        .expect("embed version resource");

    // Иконка — в debug и release.
    embed_resource::compile("icon.rc", embed_resource::NONE)
        .manifest_optional()
        .expect("embed icon.rc");

    // requireAdministrator только в release (иначе cargo test → os error 740).
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        embed_resource::compile("app.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("embed app.manifest via app.rc");
    }
}
