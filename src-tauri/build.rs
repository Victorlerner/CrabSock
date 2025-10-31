fn main() {
    // Ограничим список наблюдаемых файлов, чтобы cargo не лез в недоступные директории (например, pkg/)
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/icon.png");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=!pkg");

    // Windows: скопировать подписанный wintun.dll из репозитория в target/<profile>/resources/wintun.dll
    // чтобы dev-режим и рантайм увидели его в exe_dir/resources.
    #[cfg(target_os = "windows")]
    {
        use std::env;
        use std::fs;
        use std::path::PathBuf;
        println!("cargo:rerun-if-changed=resources/windows.manifest");
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        let target_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| manifest_dir.join("target").to_string_lossy().to_string()));

        // Map Rust target arch to Wintun folder name
        let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".into());
        let win_folder = match arch.as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "x86",
            "arm" => "arm",
            _ => "amd64",
        };

        let src = manifest_dir
            .join("resources")
            .join("wintun")
            .join("bin")
            .join(win_folder)
            .join("wintun.dll");

        let dst_dir = target_dir.join(&profile).join("resources");
        let dst = dst_dir.join("wintun.dll");
        if src.exists() {
            let _ = fs::create_dir_all(&dst_dir);
            let _ = fs::copy(&src, &dst);
            // также положим в bin\wintun.dll для поиска рантаймом
            let bin_dir = target_dir.join(&profile).join("bin");
            let _ = fs::create_dir_all(&bin_dir);
            let _ = fs::copy(&src, bin_dir.join("wintun.dll"));
        }

        // Embed Windows manifest to request administrator privileges (UAC) via .rc
        println!("cargo:rerun-if-changed=resources/windows_manifest.rc");
        embed_resource::compile("resources/windows_manifest.rc", embed_resource::NONE);
    }

    tauri_build::build()
}

