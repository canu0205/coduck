use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match coduck::cli::execute(coduck::cli::Args::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("coduck: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
