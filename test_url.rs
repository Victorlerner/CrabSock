use url::Url;

fn main() {
    let url = "ss://chacha20-ietf-poly1305:password@example.com:8388";
    println!("URL: {}", url);
    
    match Url::parse(url) {
        Ok(u) => {
            println!("Host: {:?}", u.host_str());
            println!("Port: {:?}", u.port());
            println!("Username: {:?}", u.username());
            println!("Password: {:?}", u.password());
        }
        Err(e) => println!("Error: {}", e),
    }
}
