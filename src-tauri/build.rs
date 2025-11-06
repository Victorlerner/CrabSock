fn main() {
    // Ограничим список наблюдаемых файлов, чтобы cargo не лез в недоступные директории (например, pkg/)
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/icon.png");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=!pkg");
    println!("cargo:rerun-if-changed=resources/sing-box/sing-box.exe");
    println!("cargo:rerun-if-changed=resources/openvpn_win/");
    println!("cargo:rerun-if-changed=resources/openvpn_macos/");

    // Windows-specific setup
    #[cfg(target_os = "windows")]
    {
        use std::env;
        use std::fs;
        use std::path::PathBuf;
        println!("cargo:rerun-if-changed=resources/windows.manifest");
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        let target_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| manifest_dir.join("target").to_string_lossy().to_string()));

        fn copy_dir_all(src: &PathBuf, dst: &PathBuf) {
            if let Err(_e) = std::fs::create_dir_all(dst) { return; }
            if let Ok(entries) = std::fs::read_dir(src) {
                for e in entries.flatten() {
                    let p = e.path();
                    let to = dst.join(e.file_name());
                    if p.is_dir() { copy_dir_all(&p, &to); } else { let _ = std::fs::copy(&p, &to); }
                }
            }
        }

        // Copy sing-box.exe next to resources for dev/runtime discovery and include in bundle resources
        let sing_src = manifest_dir
            .join("resources")
            .join("sing-box")
            .join("sing-box.exe");
        if sing_src.exists() {
            let sing_dst_dir = target_dir.join(&profile).join("resources").join("sing-box");
            let _ = fs::create_dir_all(&sing_dst_dir);
            let _ = fs::copy(&sing_src, sing_dst_dir.join("sing-box.exe"));
            // optional: also place in bin for direct lookup
            let bin_dir = target_dir.join(&profile).join("bin");
            let _ = fs::create_dir_all(&bin_dir);
            let _ = fs::copy(&sing_src, bin_dir.join("sing-box.exe"));
        }

        // Copy OpenVPN for Windows (both arch folders if present)
        let ovpn_win_root = manifest_dir.join("resources").join("openvpn_win");
        let dst_root = target_dir.join(&profile).join("resources").join("openvpn_win");
        for arch in ["openvpn_amd64", "openvpn_arm64"].iter() {
            let src = ovpn_win_root.join(arch);
            if src.exists() {
                let dst = dst_root.join(arch);
                copy_dir_all(&src, &dst);
            }
        }

        // Embed Windows manifest to request administrator privileges (UAC) via .rc
        println!("cargo:rerun-if-changed=resources/windows_manifest.rc");
        embed_resource::compile("resources/windows_manifest.rc", embed_resource::NONE);
    }

    // macOS-specific setup: copy openvpn_macos into target resources for dev/runtime discovery
    #[cfg(target_os = "macos")]
    {
        use std::env;
        use std::path::PathBuf;

        fn copy_dir_all(src: &PathBuf, dst: &PathBuf) {
            if let Err(_e) = std::fs::create_dir_all(dst) { return; }
            if let Ok(entries) = std::fs::read_dir(src) {
                for e in entries.flatten() {
                    let p = e.path();
                    let to = dst.join(e.file_name());
                    if p.is_dir() { copy_dir_all(&p, &to); } else { let _ = std::fs::copy(&p, &to); }
                }
            }
        }

        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        let target_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| manifest_dir.join("target").to_string_lossy().to_string()));

        let ovpn_macos_src = manifest_dir.join("resources").join("openvpn_macos");
        if ovpn_macos_src.exists() {
            let dst = target_dir.join(&profile).join("resources").join("openvpn_macos");
            copy_dir_all(&ovpn_macos_src, &dst);
        }
    }

    tauri_build::build()
}

