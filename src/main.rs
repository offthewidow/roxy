use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::sync::Arc;
use rustls::{ContentType, HandshakeType, ProtocolVersion};
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::{HandshakeMessagePayload, HandshakePayload, ServerNamePayload};
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::{io, task};
use tracing::{debug, error, info};

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
  listen_addr: Box<str>,
  rules: Rules,
}

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt::init();

  let (listen_addr, rules) = match fs::read_to_string(CONFIG_PATH) {
    Ok(raw_config) => match toml::from_str::<Config>(&raw_config) {
      Ok(config) => (config.listen_addr, Arc::new(config.rules)),
      Err(err) => return error!("could not parse config: {}", err),
    },
    Err(err) => return error!("could not read config: {}", err),
  };

  let listener = match TcpListener::bind(listen_addr.as_ref()).await {
    Ok(listener) => listener,
    Err(err) => return error!("could not bind: {}", err),
  };

  info!("listening on {}", listen_addr);

  loop {
    let stream = match listener.accept().await {
      Ok((stream, _)) => stream,
      Err(err) => return error!("could not accept: {}", err),
    };

    let rules = rules.clone();

    task::spawn(async move {
      if let Err(err) = handle_stream(rules, stream).await {
        debug!("{}", err);
      }
    });
  }
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
    return Err(rustls::Error::CorruptMessagePayload(ContentType::Handshake).into());
  }

  let mut buf = vec![0; RECORD_HEADER_LENGTH + handshake_length];

  if stream.peek(&mut buf).await? != RECORD_HEADER_LENGTH + handshake_length {
    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
  }

  let mut reader = Reader::init(&buf);

  reader.take(RECORD_HEADER_LENGTH);

  let handshake = HandshakeMessagePayload::read_version(&mut reader, protocol_version).unwrap();
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
    ServerNamePayload::HostName((_, hostname)) => AsRef::<str>::as_ref(hostname),
    ServerNamePayload::Unknown(_) => return Err("unknown SNI payload".into()),
  };

  if let Some(rule) = rules.get(hostname) {
    io::copy_bidirectional(&mut stream, &mut TcpStream::connect(rule.host.as_ref()).await?).await?;
    return Ok(());
  }

  Err("hostname not configured".into())
}