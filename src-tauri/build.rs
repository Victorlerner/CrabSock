fn main() {
    // Ограничим список наблюдаемых файлов, чтобы cargo не лез в недоступные директории (например, pkg/)
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/icon.png");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=!pkg");

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

        // Embed Windows manifest to request administrator privileges (UAC) via .rc
        println!("cargo:rerun-if-changed=resources/windows_manifest.rc");
        embed_resource::compile("resources/windows_manifest.rc", embed_resource::NONE);
    }

    tauri_build::build()
}

