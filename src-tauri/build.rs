fn main() {
    // Ограничим список наблюдаемых файлов, чтобы cargo не лез в недоступные директории (например, pkg/)
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/icon.png");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=!pkg");
    tauri_build::build()
}

