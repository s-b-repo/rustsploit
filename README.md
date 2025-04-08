Building & Running

    Clone or create this directory structure locally:

git clone https://github.com/s-b-repo/r-routersploit.git

cd r-routersploit

Build:

cargo build

Run (CLI mode), for example:

#  exploit subcommand
cargo run -- --command exploit --module sample_exploit --target 192.168.1.1

#  scanner subcommand
cargo run -- --command scanner --module sample_scanner --target 192.168.1.1

# : creds subcommand
cargo run -- --command creds --module sample_cred_check -target 192.168.1.1

Run (interactive shell mode), no arguments:

cargo run

Within the shell, you can do:

rsf> help
rsf> modules
rsf> use exploits/sample_exploit
rsf> set target 192.168.1.1
rsf> run
