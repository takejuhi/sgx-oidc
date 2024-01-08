use anyhow::Result;
use p256::{PublicKey, SecretKey};
use reqwest::Client;
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let mut socket = TcpStream::connect("localhost:54321")?;

    // let mut buf = String::new();
    // let _n = socket.read_to_string(&mut buf)?;

    // println!("{}", extract_redirect_uri(buf)?);

    auth().await?;

    send_idpair(&mut socket, b"takelab2@gmail.com", b"thisismykey")?;

    // let uri = extract_redirect_uri(buf)?;
    // println!("url: {uri}\n");

    // let listener = TcpListener::bind("localhost:22222")?;
    // let (mut sock, _addr) = listener.accept()?;

    // let mut buf = String::new();
    // let _n = sock.read_to_string(&mut buf)?;
    // println!("{buf}");

    Ok(())
}

fn send_idpair(stream: &mut TcpStream, id: &[u8], key: &[u8]) -> Result<()> {
    stream.set_nonblocking(false);

    stream.write(id)?;
    println!("send id");
    stream.flush()?;

    stream.write(key)?;
    println!("send key");
    stream.flush()?;

    Ok(())
}

fn extract_redirect_uri(res: String) -> Result<String> {
    let pat = "Location: ";
    let x = res.find(pat).unwrap();
    Ok(res[x + pat.len()..].to_string())
}

async fn auth() -> Result<()> {
    let token_response = Client::new()
        .get("https://accounts.google.com/o/oauth2/v2/auth")
        .header("Host", "https://accounts.google.com")
        .query(&[
            ("response_type", "id_token"),
            (
                "client_id",
                "1001771408255-pc3su16mforld2to3mmlur9i1p3s6c6o.apps.googleusercontent.com",
            ),
            ("redirect_uri", "https://google.com"),
            ("scope", "email%20openid"),
            ("nonce", "12345"),
        ])
        .send()
        .await?;
    println!("response:\n{token_response:#?}");
    Ok(())
}
