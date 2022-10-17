# Basic example Axum server with TLS (using Rustls)

To run this example:
- Generate a valid key/cert pair for the server and place them somewhere accessible (preferably in this folder).
- Rename `.env-example` to `.env` and replace the placeholder values with the paths to the key and cert files.
- Run the server with `cargo run`. The server will be accessible at `https://localhost:5000`.