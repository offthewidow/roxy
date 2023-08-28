use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::sync::Arc;
use axum::extract::Host;
use axum::handler::HandlerWithoutStateExt;
use axum::http::{StatusCode, Uri};
use axum::http::uri::Scheme;
use axum::response::Redirect;
use rustls::{ContentType, HandshakeType, ProtocolVersion};
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::{HandshakeMessagePayload, HandshakePayload, ServerNamePayload};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::{io, task};
use tracing::{debug, error, info, warn};

const CONFIG_PATH: &str = "config.toml";
const RECORD_HEADER_LENGTH: usize = 5; // https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_record
const MAX_HANDSHAKE_LENGTH: usize = 2048;

#[derive(Deserialize)]
struct Rule {
  host: Box<str>,
}

type Rules = HashMap<Box<str>, Rule>;

#[derive(Deserialize)]
struct Config {
  rules: Rules,
}

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt::init();

  let rules = match fs::read_to_string(CONFIG_PATH) {
    Ok(raw_config) => match toml::from_str::<Config>(&raw_config) {
      Ok(config) => Arc::new(config.rules),
      Err(err) => return error!("could not parse config: {}", err),
    },
    Err(err) => return error!("could not read config: {}", err),
  };

  info!("listening on ports 80 and 443");

  let res = tokio::try_join!(
    flatten(task::spawn(listen_tcp(rules))),
    flatten(task::spawn(listen_http())),
  );

  error!("early return: {res:?}");
}

async fn flatten<T, E: Error + 'static>(handle: task::JoinHandle<Result<T, E>>) -> Result<T, Box<dyn Error>> {
  match handle.await {
    Ok(Ok(ok)) => Ok(ok),
    Ok(Err(err)) => Err(err.into()),
    Err(err) => Err(err.into()),
  }
}

async fn listen_tcp(rules: Arc<Rules>) -> io::Result<()> {
  let listener = TcpListener::bind("0.0.0.0:443").await?;

  loop {
    let (stream, _) = listener.accept().await?;
    let rules = rules.clone();

    task::spawn(async move {
      if let Err(err) = handle_stream(rules, stream).await {
        debug!("{}", err);
      }
    });
  }
}

async fn listen_http() -> hyper::Result<()> {
  let redirect = move |Host(host): Host, uri: Uri| async move {
    match build_uri(host, uri) {
      Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
      Err(err) => {
        warn!("bad uri: {err}");
        Err(StatusCode::BAD_REQUEST)
      }
    }
  };

  axum::Server::bind(&([0, 0, 0, 0], 80).into()).serve(redirect.into_make_service()).await
}

fn build_uri(host: String, uri: Uri) -> Result<Uri, Box<dyn Error>> {
  let mut parts = uri.into_parts();

  parts.authority = Some(host.replace("80", "443").parse()?);
  parts.scheme = Some(Scheme::HTTPS);

  if parts.path_and_query.is_none() {
    parts.path_and_query = Some("/".parse().unwrap());
  }

  Ok(Uri::from_parts(parts)?)
}

async fn handle_stream(rules: Arc<Rules>, mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
  let mut buf = [0; RECORD_HEADER_LENGTH];

  if stream.peek(&mut buf).await? != RECORD_HEADER_LENGTH {
    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
  }

  let mut reader = Reader::init(&buf);
  let content_type = ContentType::read(&mut reader).unwrap();

  if content_type != ContentType::Handshake {
    return Err(rustls::Error::InappropriateMessage {
      expect_types: vec![ContentType::Handshake],
      got_type: content_type,
    }.into());
  }

  let protocol_version = ProtocolVersion::read(&mut reader).unwrap();
  let handshake_length = u16::read(&mut reader).unwrap() as usize;

  if handshake_length > MAX_HANDSHAKE_LENGTH {
    return Err("handshake too long".into());
  }

  let mut buf = vec![0; RECORD_HEADER_LENGTH + handshake_length];

  if stream.peek(&mut buf).await? != RECORD_HEADER_LENGTH + handshake_length {
    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
  }

  let mut reader = Reader::init(&buf);

  reader.take(RECORD_HEADER_LENGTH);

  let handshake = HandshakeMessagePayload::read_version(&mut reader, protocol_version)
    .map_err(|err| Box::<dyn Error>::from(format!("could not parse handshake: {err:?}")))?;

  let client_hello = match handshake.payload {
    HandshakePayload::ClientHello(client_hello) => client_hello,
    _ => return Err(rustls::Error::InappropriateHandshakeMessage {
      expect_types: vec![HandshakeType::ClientHello],
      got_type: handshake.typ,
    }.into()),
  };

  let sni = match client_hello.get_sni_extension() {
    Some(sni) => sni,
    None => return Err("missing SNI extension".into()),
  };

  let hostname = match &sni[0].payload {
    ServerNamePayload::HostName(name) => AsRef::<str>::as_ref(name),
    ServerNamePayload::Unknown(_) => return Err("unknown SNI payload".into()),
  };

  if let Some(rule) = rules.get(hostname) {
    io::copy_bidirectional(&mut stream, &mut TcpStream::connect(rule.host.as_ref()).await?).await?;
    return Ok(());
  }

  Err("hostname not configured".into())
}
