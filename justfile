debug_local:
    cargo run -- -v local

debug_remote:
    cargo run -- -v remote -l 127.0.0.1:8081

release_windows:
    cargo xwin build -r --target=x86_64-pc-windows-msvc

release_linux:
    cargo build -r --target=x86_64-unknown-linux-gnu

release: release_linux release_windows
    cp target/x86_64-pc-windows-msvc/release/rrproxy2.exe target/rrproxy2.exe
    cp target/x86_64-unknown-linux-gnu/release/rrproxy2 target/rrproxy2
    zip -r target/rrproxy2.zip target/rrproxy2.exe target/rrproxy2

alias dl := debug_local
alias dr := debug_remote
alias rw := release_windows
alias rl := release_linux
alias r := release
