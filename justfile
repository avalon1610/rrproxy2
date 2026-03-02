debug_local:
    cargo run -- -v local -l 0.0.0.0:8080 --full

debug_local_ws:
    cargo run -- -v local -l 0.0.0.0:8080 -f -w -c 200 -r http://172.29.3.67:8081

debug_remote:
    cargo run -- -v remote -l 0.0.0.0:8081 -p http://10.34.7.51:80 

debug_remote_ws:
    cargo run -- -v remote -l 0.0.0.0:8081 -p http://10.34.7.51:80 -w

release_windows:
    cargo xwin build -r --target=x86_64-pc-windows-msvc

release_linux:
    cargo build -r --target=x86_64-unknown-linux-gnu
    
release_musl:
    cargo build -r --target=x86_64-unknown-linux-musl

release: release_musl release_windows
    cp target/x86_64-pc-windows-msvc/release/rrproxy2.exe target/rrproxy2.exe
    cp target/x86_64-unknown-linux-musl/release/rrproxy2 target/rrproxy2
    zip -r target/rrproxy2.zip target/rrproxy2.exe target/rrproxy2

alias dl := debug_local
alias dlws := debug_local_ws
alias dr := debug_remote
alias drws := debug_remote_ws
alias rw := release_windows
alias rl := release_linux
alias rm := release_musl
alias r := release
