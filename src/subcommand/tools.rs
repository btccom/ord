use {
    self::{
      accept_encoding::AcceptEncoding,
      accept_json::AcceptJson,
      deserialize_from_str::DeserializeFromStr,
      error::{OptionExt, ServerError, ServerResult},
    },
    super::*,
    consensus::encode::deserialize,
    crate::{
      server_config::ServerConfig,
      templates::{
        BlockHtml, BlockJson, BlocksHtml, ChildrenHtml, ChildrenJson, ClockSvg, CollectionsHtml,
        HomeHtml, InputHtml, InscriptionHtml, InscriptionJson, InscriptionsBlockHtml,
        InscriptionsHtml, InscriptionsJson, OutputHtml, OutputJson, PageContent, PageHtml,
        PreviewAudioHtml, PreviewCodeHtml, PreviewFontHtml, PreviewImageHtml, PreviewMarkdownHtml,
        PreviewModelHtml, PreviewPdfHtml, PreviewTextHtml, PreviewUnknownHtml, PreviewVideoHtml,
        RangeHtml, RareTxt, RuneHtml, RunesHtml, SatHtml, SatInscriptionJson, SatInscriptionsJson,
        SatJson, StatusHtml, TransactionHtml,
      },
    },
    axum::{
      body,
      extract::{Extension, Json, Path, Query},
      headers::UserAgent,
      http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
      response::{IntoResponse, Redirect, Response},
      routing::get,
      Router, TypedHeader,
    },
    axum_server::Handle,
    brotli::Decompressor,
    rust_embed::RustEmbed,
    rustls_acme::{
      acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY},
      axum::AxumAcceptor,
      caches::DirCache,
      AcmeConfig,
    },
    std::{cmp::Ordering, io::Read, str, sync::Arc},
    tokio_stream::StreamExt,
    tower_http::{
      compression::CompressionLayer,
      cors::{Any, CorsLayer},
      set_header::SetResponseHeaderLayer,
    },
  };
  
  mod accept_encoding;
  mod accept_json;
  mod error;
  
#[derive(Copy, Clone)]
pub(crate) enum InscriptionQuery {
  Id(InscriptionId),
  Number(i32),
}

impl FromStr for InscriptionQuery {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(if s.contains('i') {
      Self::Id(s.parse()?)
    } else {
      Self::Number(s.parse()?)
    })
  }
}

impl Display for InscriptionQuery {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    match self {
      Self::Id(id) => write!(f, "{id}"),
      Self::Number(number) => write!(f, "{number}"),
    }
  }
}

enum BlockQuery {
  Height(u32),
  Hash(BlockHash),
}

impl FromStr for BlockQuery {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(if s.len() == 64 {
      BlockQuery::Hash(s.parse()?)
    } else {
      BlockQuery::Height(s.parse()?)
    })
  }
}

enum SpawnConfig {
  Https(AxumAcceptor),
  Http,
  Redirect(String),
}

#[derive(Deserialize)]
struct Search {
  query: String,
}

#[derive(RustEmbed)]
#[folder = "static"]
struct StaticAssets;

struct StaticHtml {
  title: &'static str,
  html: &'static str,
}

impl PageContent for StaticHtml {
  fn title(&self) -> String {
    self.title.into()
  }
}

impl Display for StaticHtml {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    f.write_str(self.html)
  }
}

#[derive(Debug, Parser)]
  pub(crate) struct Tools {
  #[arg(
    long,
    help = "Listen on <ADDRESS> for incoming requests. [default: 0.0.0.0]"
  )]
  address: Option<String>,
  #[arg(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  acme_domain: Vec<String>,
  #[arg(
    long,
    help = "Use <CSP_ORIGIN> in Content-Security-Policy header. Set this to the public-facing URL of your ord instance."
  )]
  csp_origin: Option<String>,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]"
  )]
  http_port: Option<u16>,
  #[arg(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]"
  )]
  https_port: Option<u16>,
  #[arg(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  acme_cache: Option<PathBuf>,
  #[arg(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  acme_contact: Vec<String>,
  #[arg(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  http: bool,
  #[arg(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  https: bool,
  #[arg(long, help = "Redirect HTTP traffic to HTTPS.")]
  redirect_http_to_https: bool,
  #[arg(long, short = 'j', help = "Enable JSON API.")]
  pub(crate) enable_json_api: bool,
  #[arg(
    long,
    help = "Decompress encoded content. Currently only supports brotli. Be careful using this on production instances. A decompressed inscription may be arbitrarily large, making decompression a DoS vector."
  )]
  pub(crate) decompress: bool,
}

  impl Tools {
    pub(crate) fn run(self, options: Options, handle: Handle) -> SubcommandResult {
      Runtime::new()?.block_on(async {
  
        let config = Arc::new(options.load_config()?);
        let acme_domains = self.acme_domains()?;
  
        let server_config = Arc::new(ServerConfig {
          chain: options.chain(),
          csp_origin: self.csp_origin.clone(),
          domain: acme_domains.first().cloned(),
          index_sats: false,
          is_json_api_enabled: self.enable_json_api,
          decompress: self.decompress,
        });
  
        let router = Router::new()
          .route("/rawtx_inscriptions/:rawtx", get(Self::rawtx_inscriptions))
        .layer(Extension(server_config.clone()))
        .layer(Extension(config))
        .layer(SetResponseHeaderLayer::if_not_present(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src 'self'"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
          header::STRICT_TRANSPORT_SECURITY,
          HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(
          CorsLayer::new()
            .allow_methods([http::Method::GET])
            .allow_origin(Any),
        )
        .layer(CompressionLayer::new())
        .with_state(server_config);

      match (self.http_port(), self.https_port()) {
        (Some(http_port), None) => {
          self
            .spawn(router, handle, http_port, SpawnConfig::Http)?
            .await??
        }
        (None, Some(https_port)) => {
          self
            .spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
            .await??
        }
        (Some(http_port), Some(https_port)) => {
          let http_spawn_config = if self.redirect_http_to_https {
            SpawnConfig::Redirect(if https_port == 443 {
              format!("https://{}", acme_domains[0])
            } else {
              format!("https://{}:{https_port}", acme_domains[0])
            })
          } else {
            SpawnConfig::Http
          };

          let (http_result, https_result) = tokio::join!(
            self.spawn(router.clone(), handle.clone(), http_port, http_spawn_config)?,
            self.spawn(
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&options)?),
            )?
          );
          http_result.and(https_result)??;
        }
        (None, None) => unreachable!(),
      }

      Ok(Box::new(Empty {}) as Box<dyn Output>)
    })
  }

  fn spawn(
    &self,
    router: Router,
    handle: Handle,
    port: u16,
    config: SpawnConfig,
  ) -> Result<task::JoinHandle<io::Result<()>>> {
    let address = match &self.address {
      Some(address) => address.as_str(),
      None => {
        if cfg!(test) || integration_test() {
          "127.0.0.1"
        } else {
          "0.0.0.0"
        }
      }
    };

    let addr = (address, port)
      .to_socket_addrs()?
      .next()
      .ok_or_else(|| anyhow!("failed to get socket addrs"))?;

    if !integration_test() {
      eprintln!(
        "Listening on {}://{addr}",
        match config {
          SpawnConfig::Https(_) => "https",
          _ => "http",
        }
      );
    }

    Ok(tokio::spawn(async move {
      match config {
        SpawnConfig::Https(acceptor) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .acceptor(acceptor)
            .serve(router.into_make_service())
            .await
        }
        SpawnConfig::Redirect(destination) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(
              Router::new()
                .fallback(Self::redirect_http_to_https)
                .layer(Extension(destination))
                .into_make_service(),
            )
            .await
        }
        SpawnConfig::Http => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await
        }
      }
    }))
  }

  fn acme_cache(acme_cache: Option<&PathBuf>, options: &Options) -> PathBuf {
    acme_cache
      .unwrap_or(&options.data_dir().join("acme-cache"))
      .to_path_buf()
  }

  fn acme_domains(&self) -> Result<Vec<String>> {
    if !self.acme_domain.is_empty() {
      Ok(self.acme_domain.clone())
    } else {
      Ok(vec![
        System::host_name().ok_or(anyhow!("no hostname found"))?
      ])
    }
  }

  fn http_port(&self) -> Option<u16> {
    if self.http || self.http_port.is_some() || (self.https_port.is_none() && !self.https) {
      Some(self.http_port.unwrap_or(80))
    } else {
      None
    }
  }

  fn https_port(&self) -> Option<u16> {
    if self.https || self.https_port.is_some() {
      Some(self.https_port.unwrap_or(443))
    } else {
      None
    }
  }

  fn acceptor(&self, options: &Options) -> Result<AxumAcceptor> {
    let config = AcmeConfig::new(self.acme_domains()?)
      .contact(&self.acme_contact)
      .cache_option(Some(DirCache::new(Self::acme_cache(
        self.acme_cache.as_ref(),
        options,
      ))))
      .directory(if cfg!(test) {
        LETS_ENCRYPT_STAGING_DIRECTORY
      } else {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
      });

    let mut state = config.state();

    let mut server_config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_cert_resolver(state.resolver());

    server_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];

    let acceptor = state.axum_acceptor(Arc::new(server_config));

    tokio::spawn(async move {
      while let Some(result) = state.next().await {
        match result {
          Ok(ok) => log::info!("ACME event: {:?}", ok),
          Err(err) => log::error!("ACME error: {:?}", err),
        }
      }
    });

    Ok(acceptor)
  }

  fn index_height(index: &Index) -> ServerResult<Height> {
    index.block_height()?.ok_or_not_found(|| "genesis block")
  }

  async fn redirect_http_to_https(
    Extension(mut destination): Extension<String>,
    uri: Uri,
  ) -> Redirect {
    if let Some(path_and_query) = uri.path_and_query() {
      destination.push_str(path_and_query.as_str());
    }

    Redirect::to(&destination)
  }
  fn get_rawtx_inscription(
    rawtx: String,
  ) -> Result<Vec<ParsedEnvelope>> {
    let transaction = deserialize::<Transaction>(hex::decode(rawtx).unwrap().as_slice()).ok();
    match transaction {
      Some(tx) => Ok(ParsedEnvelope::from_transaction(&tx)),
      None => Err(anyhow!("parse rawtx fail"))
    }
  }

  async fn rawtx_inscriptions(
    Path(rawtx): Path<String>,
  ) -> ServerResult<Response> {
    let inscription = Self::get_rawtx_inscription(rawtx)?;
    let s = serde_json::to_string(&inscription).unwrap_or_default();
    Ok(
      s.into_response()
    )
  }
}

#[cfg(test)]
mod tests {
  use {
    super::*,
    crate::runes::{Edict, Etching, Rune, Runestone},
    reqwest::Url,
    serde::de::DeserializeOwned,
    std::net::TcpListener,
  };

  const RUNE: u128 = 99246114928149462;

  struct TestServer {
    bitcoin_rpc_server: test_bitcoincore_rpc::Handle,
    index: Arc<Index>,
    ord_server_handle: Handle,
    url: Url,
    #[allow(unused)]
    tempdir: TempDir,
  }

  impl TestServer {
    fn new() -> Self {
      Self::new_with_args(&[], &[])
    }

    fn new_with_sat_index() -> Self {
      Self::new_with_args(&["--index-sats"], &[])
    }

    fn new_with_args(ord_args: &[&str], server_args: &[&str]) -> Self {
      Self::new_server(test_bitcoincore_rpc::spawn(), None, ord_args, server_args)
    }

    fn new_with_regtest() -> Self {
      Self::new_server(
        test_bitcoincore_rpc::builder()
          .network(bitcoin::network::constants::Network::Regtest)
          .build(),
        None,
        &["--chain", "regtest"],
        &[],
      )
    }

    fn new_with_regtest_with_json_api() -> Self {
      Self::new_server(
        test_bitcoincore_rpc::builder()
          .network(bitcoin::network::constants::Network::Regtest)
          .build(),
        None,
        &["--chain", "regtest"],
        &["--enable-json-api"],
      )
    }

    fn new_with_regtest_with_index_sats() -> Self {
      Self::new_server(
        test_bitcoincore_rpc::builder()
          .network(bitcoin::Network::Regtest)
          .build(),
        None,
        &["--chain", "regtest", "--index-sats"],
        &[],
      )
    }

    fn new_with_regtest_with_index_runes() -> Self {
      Self::new_server(
        test_bitcoincore_rpc::builder()
          .network(bitcoin::Network::Regtest)
          .build(),
        None,
        &["--chain", "regtest", "--index-runes"],
        &["--enable-json-api"],
      )
    }

    fn new_with_bitcoin_rpc_server_and_config(
      bitcoin_rpc_server: test_bitcoincore_rpc::Handle,
      config: String,
    ) -> Self {
      Self::new_server(bitcoin_rpc_server, Some(config), &[], &[])
    }

    fn new_server(
      bitcoin_rpc_server: test_bitcoincore_rpc::Handle,
      config: Option<String>,
      ord_args: &[&str],
      server_args: &[&str],
    ) -> Self {
      let tempdir = TempDir::new().unwrap();

      let cookiefile = tempdir.path().join("cookie");

      fs::write(&cookiefile, "username:password").unwrap();

      let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

      let url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();

      let config_args = match config {
        Some(config) => {
          let config_path = tempdir.path().join("ord.yaml");
          fs::write(&config_path, config).unwrap();
          format!("--config {}", config_path.display())
        }
        None => "".to_string(),
      };

      let (options, server) = parse_server_args(&format!(
        "ord --rpc-url {} --cookie-file {} --data-dir {} {config_args} {} server --http-port {} --address 127.0.0.1 {}",
        bitcoin_rpc_server.url(),
        cookiefile.to_str().unwrap(),
        tempdir.path().to_str().unwrap(),
        ord_args.join(" "),
        port,
        server_args.join(" "),
      ));

      let index = Arc::new(Index::open(&options).unwrap());
      let ord_server_handle = Handle::new();

      {
        let index = index.clone();
        let ord_server_handle = ord_server_handle.clone();
        thread::spawn(|| server.run(options, index, ord_server_handle).unwrap());
      }

      while index.statistic(crate::index::Statistic::Commits) == 0 {
        thread::sleep(Duration::from_millis(25));
      }

      let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

      for i in 0.. {
        match client.get(format!("http://127.0.0.1:{port}/status")).send() {
          Ok(_) => break,
          Err(err) => {
            if i == 400 {
              panic!("server failed to start: {err}");
            }
          }
        }

        thread::sleep(Duration::from_millis(25));
      }

      Self {
        bitcoin_rpc_server,
        index,
        ord_server_handle,
        tempdir,
        url,
      }
    }

    fn get(&self, path: impl AsRef<str>) -> reqwest::blocking::Response {
      if let Err(error) = self.index.update() {
        log::error!("{error}");
      }
      reqwest::blocking::get(self.join_url(path.as_ref())).unwrap()
    }

    pub(crate) fn get_json<T: DeserializeOwned>(&self, path: impl AsRef<str>) -> T {
      if let Err(error) = self.index.update() {
        log::error!("{error}");
      }

      let client = reqwest::blocking::Client::new();

      let response = client
        .get(self.join_url(path.as_ref()))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .unwrap();

      assert_eq!(response.status(), StatusCode::OK);

      response.json().unwrap()
    }

    fn join_url(&self, url: &str) -> Url {
      self.url.join(url).unwrap()
    }

    fn assert_response(&self, path: impl AsRef<str>, status: StatusCode, expected_response: &str) {
      let response = self.get(path);
      assert_eq!(response.status(), status, "{}", response.text().unwrap());
      pretty_assert_eq!(response.text().unwrap(), expected_response);
    }

    #[track_caller]
    fn assert_response_regex(
      &self,
      path: impl AsRef<str>,
      status: StatusCode,
      regex: impl AsRef<str>,
    ) {
      let response = self.get(path);
      assert_eq!(response.status(), status);
      assert_regex_match!(response.text().unwrap(), regex.as_ref());
    }

    fn assert_response_csp(
      &self,
      path: impl AsRef<str>,
      status: StatusCode,
      content_security_policy: &str,
      regex: impl AsRef<str>,
    ) {
      let response = self.get(path);
      assert_eq!(response.status(), status);
      assert_eq!(
        response
          .headers()
          .get(header::CONTENT_SECURITY_POLICY,)
          .unwrap(),
        content_security_policy
      );
      assert_regex_match!(response.text().unwrap(), regex.as_ref());
    }

    #[track_caller]
    fn assert_redirect(&self, path: &str, location: &str) {
      let response = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(self.join_url(path))
        .send()
        .unwrap();

      assert_eq!(response.status(), StatusCode::SEE_OTHER);
      assert_eq!(response.headers().get(header::LOCATION).unwrap(), location);
    }

    fn mine_blocks(&self, n: u64) -> Vec<bitcoin::Block> {
      let blocks = self.bitcoin_rpc_server.mine_blocks(n);
      self.index.update().unwrap();
      blocks
    }

    fn mine_blocks_with_subsidy(&self, n: u64, subsidy: u64) -> Vec<Block> {
      let blocks = self.bitcoin_rpc_server.mine_blocks_with_subsidy(n, subsidy);
      self.index.update().unwrap();
      blocks
    }
  }

  impl Drop for TestServer {
    fn drop(&mut self) {
      self.ord_server_handle.shutdown();
    }
  }

  fn parse_server_args(args: &str) -> (Options, Server) {
    match Arguments::try_parse_from(args.split_whitespace()) {
      Ok(arguments) => match arguments.subcommand {
        Subcommand::Server(server) => (arguments.options, server),
        subcommand => panic!("unexpected subcommand: {subcommand:?}"),
      },
      Err(err) => panic!("error parsing arguments: {err}"),
    }
  }

  #[test]
  fn http_and_https_port_dont_conflict() {
    parse_server_args(
      "ord server --http-port 0 --https-port 0 --acme-cache foo --acme-contact bar --acme-domain baz",
    );
  }

  #[test]
  fn http_port_defaults_to_80() {
    assert_eq!(parse_server_args("ord server").1.http_port(), Some(80));
  }

  #[test]
  fn https_port_defaults_to_none() {
    assert_eq!(parse_server_args("ord server").1.https_port(), None);
  }

  #[test]
  fn https_sets_https_port_to_443() {
    assert_eq!(
      parse_server_args("ord server --https --acme-cache foo --acme-contact bar --acme-domain baz")
        .1
        .https_port(),
      Some(443)
    );
  }

  #[test]
  fn https_disables_http() {
    assert_eq!(
      parse_server_args("ord server --https --acme-cache foo --acme-contact bar --acme-domain baz")
        .1
        .http_port(),
      None
    );
  }

  #[test]
  fn https_port_disables_http() {
    assert_eq!(
      parse_server_args(
        "ord server --https-port 433 --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .http_port(),
      None
    );
  }

  #[test]
  fn https_port_sets_https_port() {
    assert_eq!(
      parse_server_args(
        "ord server --https-port 1000 --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .https_port(),
      Some(1000)
    );
  }

  #[test]
  fn http_with_https_leaves_http_enabled() {
    assert_eq!(
      parse_server_args(
        "ord server --https --http --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .http_port(),
      Some(80)
    );
  }

  #[test]
  fn http_with_https_leaves_https_enabled() {
    assert_eq!(
      parse_server_args(
        "ord server --https --http --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .https_port(),
      Some(443)
    );
  }

  #[test]
  fn acme_contact_accepts_multiple_values() {
    assert!(Arguments::try_parse_from([
      "ord",
      "server",
      "--address",
      "127.0.0.1",
      "--http-port",
      "0",
      "--acme-contact",
      "foo",
      "--acme-contact",
      "bar"
    ])
    .is_ok());
  }

  #[test]
  fn acme_domain_accepts_multiple_values() {
    assert!(Arguments::try_parse_from([
      "ord",
      "server",
      "--address",
      "127.0.0.1",
      "--http-port",
      "0",
      "--acme-domain",
      "foo",
      "--acme-domain",
      "bar"
    ])
    .is_ok());
  }

  #[test]
  fn acme_cache_defaults_to_data_dir() {
    let arguments = Arguments::try_parse_from(["ord", "--data-dir", "foo", "server"]).unwrap();
    let acme_cache = Server::acme_cache(None, &arguments.options)
      .display()
      .to_string();
    assert!(
      acme_cache.contains(if cfg!(windows) {
        r"foo\acme-cache"
      } else {
        "foo/acme-cache"
      }),
      "{acme_cache}"
    )
  }

  #[test]
  fn acme_cache_flag_is_respected() {
    let arguments =
      Arguments::try_parse_from(["ord", "--data-dir", "foo", "server", "--acme-cache", "bar"])
        .unwrap();
    let acme_cache = Server::acme_cache(Some(&"bar".into()), &arguments.options)
      .display()
      .to_string();
    assert_eq!(acme_cache, "bar")
  }

  #[test]
  fn acme_domain_defaults_to_hostname() {
    let (_, server) = parse_server_args("ord server");
    assert_eq!(
      server.acme_domains().unwrap(),
      &[System::host_name().unwrap()]
    );
  }

  #[test]
  fn acme_domain_flag_is_respected() {
    let (_, server) = parse_server_args("ord server --acme-domain example.com");
    assert_eq!(server.acme_domains().unwrap(), &["example.com"]);
  }

  #[test]
  fn install_sh_redirects_to_github() {
    TestServer::new().assert_redirect(
      "/install.sh",
      "https://raw.githubusercontent.com/ordinals/ord/master/install.sh",
    );
  }

  #[test]
  fn ordinal_redirects_to_sat() {
    TestServer::new().assert_redirect("/ordinal/0", "/sat/0");
  }

  #[test]
  fn bounties_redirects_to_docs_site() {
    TestServer::new().assert_redirect("/bounties", "https://docs.ordinals.com/bounty/");
  }

  #[test]
  fn faq_redirects_to_docs_site() {
    TestServer::new().assert_redirect("/faq", "https://docs.ordinals.com/faq/");
  }

  #[test]
  fn search_by_query_returns_sat() {
    TestServer::new().assert_redirect("/search?query=0", "/sat/0");
  }

  #[test]
  fn search_by_query_returns_rune() {
    TestServer::new().assert_redirect("/search?query=ABCD", "/rune/ABCD");
  }

  #[test]
  fn search_by_query_returns_spaced_rune() {
    TestServer::new().assert_redirect("/search?query=AB•CD", "/rune/AB•CD");
  }

  #[test]
  fn search_by_query_returns_inscription() {
    TestServer::new().assert_redirect(
      "/search?query=0000000000000000000000000000000000000000000000000000000000000000i0",
      "/inscription/0000000000000000000000000000000000000000000000000000000000000000i0",
    );
  }

  #[test]
  fn search_is_whitespace_insensitive() {
    TestServer::new().assert_redirect("/search/ 0 ", "/sat/0");
  }

  #[test]
  fn search_by_path_returns_sat() {
    TestServer::new().assert_redirect("/search/0", "/sat/0");
  }

  #[test]
  fn search_for_blockhash_returns_block() {
    TestServer::new().assert_redirect(
      "/search/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      "/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
  }

  #[test]
  fn search_for_txid_returns_transaction() {
    TestServer::new().assert_redirect(
      "/search/0000000000000000000000000000000000000000000000000000000000000000",
      "/tx/0000000000000000000000000000000000000000000000000000000000000000",
    );
  }

  #[test]
  fn search_for_outpoint_returns_output() {
    TestServer::new().assert_redirect(
      "/search/0000000000000000000000000000000000000000000000000000000000000000:0",
      "/output/0000000000000000000000000000000000000000000000000000000000000000:0",
    );
  }

  #[test]
  fn search_for_inscription_id_returns_inscription() {
    TestServer::new().assert_redirect(
      "/search/0000000000000000000000000000000000000000000000000000000000000000i0",
      "/inscription/0000000000000000000000000000000000000000000000000000000000000000i0",
    );
  }

  #[test]
  fn search_by_path_returns_rune() {
    TestServer::new().assert_redirect("/search/ABCD", "/rune/ABCD");
  }

  #[test]
  fn search_by_path_returns_spaced_rune() {
    TestServer::new().assert_redirect("/search/AB•CD", "/rune/AB•CD");
  }

  #[test]
  fn search_by_rune_id_returns_rune() {
    let server = TestServer::new_with_regtest_with_index_runes();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::max_value(),
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(rune),
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_redirect("/search/2/1", "/rune/AAAAAAAAAAAAA");
    server.assert_redirect("/search?query=2/1", "/rune/AAAAAAAAAAAAA");

    server.assert_response_regex("/rune/100/200", StatusCode::NOT_FOUND, ".*");

    server.assert_response_regex(
      "/search/100000000000000000000/200000000000000000",
      StatusCode::BAD_REQUEST,
      ".*",
    );
  }

  #[test]
  fn runes_are_displayed_on_runes_page() {
    let server = TestServer::new_with_regtest_with_index_runes();

    server.mine_blocks(1);

    server.assert_response_regex(
      "/runes",
      StatusCode::OK,
      ".*<title>Runes</title>.*<h1>Runes</h1>\n<ul>\n</ul>.*",
    );

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::max_value(),
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(Rune(RUNE)),
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = RuneId {
      height: 2,
      index: 1,
    };

    assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::max_value(),
          timestamp: 2,
          ..Default::default()
        }
      )]
    );

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::max_value())])]
    );

    server.assert_response_regex(
      "/runes",
      StatusCode::OK,
      ".*<title>Runes</title>.*
<h1>Runes</h1>
<ul>
  <li><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></li>
</ul>.*",
    );
  }

  #[test]
  fn runes_are_displayed_on_rune_page() {
    let server = TestServer::new_with_regtest_with_index_runes();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::max_value(),
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(rune),
            symbol: Some('%'),
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = RuneId {
      height: 2,
      index: 1,
    };

    assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          etching: txid,
          rune,
          supply: u128::max_value(),
          symbol: Some('%'),
          timestamp: 2,
          ..Default::default()
        }
      )]
    );

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::max_value())])]
    );

    server.assert_response_regex(
      format!("/rune/{rune}"),
      StatusCode::OK,
      format!(
        ".*<title>Rune AAAAAAAAAAAAA</title>.*
<h1>AAAAAAAAAAAAA</h1>
<iframe .* src=/preview/{txid}i0></iframe>
<dl>
  <dt>number</dt>
  <dd>0</dd>
  <dt>timestamp</dt>
  <dd><time>1970-01-01 00:00:02 UTC</time></dd>
  <dt>id</dt>
  <dd>2/1</dd>
  <dt>etching block height</dt>
  <dd><a href=/block/2>2</a></dd>
  <dt>etching transaction index</dt>
  <dd>1</dd>
  <dt>mints</dt>
  <dd>0</dd>
  <dt>supply</dt>
  <dd>340282366920938463463374607431768211455\u{00A0}%</dd>
  <dt>burned</dt>
  <dd>0\u{00A0}%</dd>
  <dt>divisibility</dt>
  <dd>0</dd>
  <dt>symbol</dt>
  <dd>%</dd>
  <dt>etching</dt>
  <dd><a class=monospace href=/tx/{txid}>{txid}</a></dd>
  <dt>parent</dt>
  <dd><a class=monospace href=/inscription/{txid}i0>{txid}i0</a></dd>
</dl>
.*"
      ),
    );

    server.assert_response_regex(
      format!("/inscription/{txid}i0"),
      StatusCode::OK,
      ".*
<dl>
  .*
  <dt>rune</dt>
  <dd><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></dd>
</dl>
.*",
    );
  }

  #[test]
  fn runes_are_spaced() {
    let server = TestServer::new_with_regtest_with_index_runes();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::max_value(),
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(rune),
            symbol: Some('%'),
            spacers: 1,
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = RuneId {
      height: 2,
      index: 1,
    };

    assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          etching: txid,
          rune,
          supply: u128::max_value(),
          symbol: Some('%'),
          timestamp: 2,
          spacers: 1,
          ..Default::default()
        }
      )]
    );

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::max_value())])]
    );

    server.assert_response_regex(
      format!("/rune/{rune}"),
      StatusCode::OK,
      r".*<title>Rune A•AAAAAAAAAAAA</title>.*<h1>A•AAAAAAAAAAAA</h1>.*",
    );

    server.assert_response_regex(
      format!("/inscription/{txid}i0"),
      StatusCode::OK,
      ".*<dt>rune</dt>.*<dd><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></dd>.*",
    );

    server.assert_response_regex(
      "/runes",
      StatusCode::OK,
      ".*<li><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></li>.*",
    );

    server.assert_response_regex(
      format!("/tx/{txid}"),
      StatusCode::OK,
      ".*
  <dt>etching</dt>
  <dd><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></dd>
.*",
    );

    server.assert_response_regex(
      format!("/output/{txid}:0"),
      StatusCode::OK,
      ".*<tr>
        <td><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></td>
        <td>340282366920938463463374607431768211455\u{00A0}%</td>
      </tr>.*",
    );
  }

  #[test]
  fn transactions_link_to_etching() {
    let server = TestServer::new_with_regtest_with_index_runes();

    server.mine_blocks(1);

    server.assert_response_regex(
      "/runes",
      StatusCode::OK,
      ".*<title>Runes</title>.*<h1>Runes</h1>\n<ul>\n</ul>.*",
    );

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::max_value(),
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(Rune(RUNE)),
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = RuneId {
      height: 2,
      index: 1,
    };

    assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::max_value(),
          timestamp: 2,
          ..Default::default()
        }
      )]
    );

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::max_value())])]
    );

    server.assert_response_regex(
      format!("/tx/{txid}"),
      StatusCode::OK,
      ".*
  <dt>etching</dt>
  <dd><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></dd>
.*",
    );
  }

  #[test]
  fn runes_are_displayed_on_output_page() {
    let server = TestServer::new_with_regtest_with_index_runes();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::max_value(),
            output: 0,
          }],
          etching: Some(Etching {
            divisibility: 1,
            rune: Some(rune),
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = RuneId {
      height: 2,
      index: 1,
    };

    assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          divisibility: 1,
          etching: txid,
          rune,
          supply: u128::max_value(),
          timestamp: 2,
          ..Default::default()
        }
      )]
    );

    let output = OutPoint { txid, vout: 0 };

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(output, vec![(id, u128::max_value())])]
    );

    server.assert_response_regex(
      format!("/output/{output}"),
      StatusCode::OK,
      format!(
        ".*<title>Output {output}</title>.*<h1>Output <span class=monospace>{output}</span></h1>.*
  <dt>runes</dt>
  <dd>
    <table>
      <tr>
        <th>rune</th>
        <th>balance</th>
      </tr>
      <tr>
        <td><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></td>
        <td>34028236692093846346337460743176821145.5</td>
      </tr>
    </table>
  </dd>
.*"
      ),
    );

    assert_eq!(
      server.get_json::<OutputJson>(format!("/output/{output}")),
      OutputJson {
        value: 5000000000,
        script_pubkey: String::new(),
        address: None,
        transaction: txid.to_string(),
        sat_ranges: None,
        inscriptions: Vec::new(),
        runes: vec![(Rune(RUNE), 340282366920938463463374607431768211455)]
          .into_iter()
          .collect(),
      }
    );
  }

  #[test]
  fn http_to_https_redirect_with_path() {
    TestServer::new_with_args(&[], &["--redirect-http-to-https", "--https"]).assert_redirect(
      "/sat/0",
      &format!("https://{}/sat/0", System::host_name().unwrap()),
    );
  }

  #[test]
  fn http_to_https_redirect_with_empty() {
    TestServer::new_with_args(&[], &["--redirect-http-to-https", "--https"])
      .assert_redirect("/", &format!("https://{}/", System::host_name().unwrap()));
  }

  #[test]
  fn status() {
    let test_server = TestServer::new();

    test_server.assert_response_regex(
      "/status",
      StatusCode::OK,
      ".*<h1>Status</h1>
<dl>
  <dt>height</dt>
  <dd>0</dd>
  <dt>inscriptions</dt>
  <dd>0</dd>
  <dt>blessed inscriptions</dt>
  <dd>0</dd>
  <dt>cursed inscriptions</dt>
  <dd>0</dd>
  <dt>runes</dt>
  <dd>0</dd>
  <dt>lost sats</dt>
  <dd>.*</dd>
  <dt>started</dt>
  <dd>.*</dd>
  <dt>uptime</dt>
  <dd>.*</dd>
  <dt>minimum rune for next block</dt>
  <dd>AAAAAAAAAAAAA</dd>
  <dt>version</dt>
  <dd>.*</dd>
  <dt>unrecoverably reorged</dt>
  <dd>false</dd>
  <dt>rune index</dt>
  <dd>false</dd>
  <dt>sat index</dt>
  <dd>false</dd>
  <dt>transaction index</dt>
  <dd>false</dd>
  <dt>git branch</dt>
  <dd>.*</dd>
  <dt>git commit</dt>
  <dd>
    <a href=https://github.com/ordinals/ord/commit/[[:xdigit:]]{40}>
      [[:xdigit:]]{40}
    </a>
  </dd>
</dl>
.*",
    );
  }

  #[test]
  fn block_count_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockcount");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "1");

    test_server.mine_blocks(1);

    let response = test_server.get("/blockcount");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "2");
  }

  #[test]
  fn block_height_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockheight");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "0");

    test_server.mine_blocks(2);

    let response = test_server.get("/blockheight");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "2");
  }

  #[test]
  fn block_hash_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockhash");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.text().unwrap(),
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
  }

  #[test]
  fn block_hash_from_height_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockhash/0");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.text().unwrap(),
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
  }

  #[test]
  fn block_time_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blocktime");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "1231006505");
  }

  #[test]
  fn range_end_before_range_start_returns_400() {
    TestServer::new().assert_response(
      "/range/1/0",
      StatusCode::BAD_REQUEST,
      "range start greater than range end",
    );
  }

  #[test]
  fn invalid_range_start_returns_400() {
    TestServer::new().assert_response(
      "/range/=/0",
      StatusCode::BAD_REQUEST,
      "Invalid URL: invalid digit found in string",
    );
  }

  #[test]
  fn invalid_range_end_returns_400() {
    TestServer::new().assert_response(
      "/range/0/=",
      StatusCode::BAD_REQUEST,
      "Invalid URL: invalid digit found in string",
    );
  }

  #[test]
  fn empty_range_returns_400() {
    TestServer::new().assert_response("/range/0/0", StatusCode::BAD_REQUEST, "empty range");
  }

  #[test]
  fn range() {
    TestServer::new().assert_response_regex(
      "/range/0/1",
      StatusCode::OK,
      r".*<title>Sat range 0–1</title>.*<h1>Sat range 0–1</h1>
<dl>
  <dt>value</dt><dd>1</dd>
  <dt>first</dt><dd><a href=/sat/0 class=mythic>0</a></dd>
</dl>.*",
    );
  }
  #[test]
  fn sat_number() {
    TestServer::new().assert_response_regex("/sat/0", StatusCode::OK, ".*<h1>Sat 0</h1>.*");
  }

  #[test]
  fn sat_decimal() {
    TestServer::new().assert_response_regex("/sat/0.0", StatusCode::OK, ".*<h1>Sat 0</h1>.*");
  }

  #[test]
  fn sat_degree() {
    TestServer::new().assert_response_regex("/sat/0°0′0″0‴", StatusCode::OK, ".*<h1>Sat 0</h1>.*");
  }

  #[test]
  fn sat_name() {
    TestServer::new().assert_response_regex(
      "/sat/nvtdijuwxlp",
      StatusCode::OK,
      ".*<h1>Sat 0</h1>.*",
    );
  }

  #[test]
  fn sat() {
    TestServer::new().assert_response_regex(
      "/sat/0",
      StatusCode::OK,
      ".*<title>Sat 0</title>.*<h1>Sat 0</h1>.*",
    );
  }

  #[test]
  fn block() {
    TestServer::new().assert_response_regex(
      "/block/0",
      StatusCode::OK,
      ".*<title>Block 0</title>.*<h1>Block 0</h1>.*",
    );
  }

  #[test]
  fn sat_out_of_range() {
    TestServer::new().assert_response(
      "/sat/2099999997690000",
      StatusCode::BAD_REQUEST,
      "Invalid URL: invalid sat",
    );
  }

  #[test]
  fn invalid_outpoint_hash_returns_400() {
    TestServer::new().assert_response(
      "/output/foo:0",
      StatusCode::BAD_REQUEST,
      "Invalid URL: error parsing TXID",
    );
  }

  #[test]
  fn output_with_sat_index() {
    let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    TestServer::new_with_sat_index().assert_response_regex(
      format!("/output/{txid}:0"),
      StatusCode::OK,
      format!(
        ".*<title>Output {txid}:0</title>.*<h1>Output <span class=monospace>{txid}:0</span></h1>
<dl>
  <dt>value</dt><dd>5000000000</dd>
  <dt>script pubkey</dt><dd class=monospace>OP_PUSHBYTES_65 [[:xdigit:]]{{130}} OP_CHECKSIG</dd>
  <dt>transaction</dt><dd><a class=monospace href=/tx/{txid}>{txid}</a></dd>
</dl>
<h2>1 Sat Range</h2>
<ul class=monospace>
  <li><a href=/range/0/5000000000 class=mythic>0–5000000000</a></li>
</ul>.*"
      ),
    );
  }

  #[test]
  fn output_without_sat_index() {
    let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    TestServer::new().assert_response_regex(
      format!("/output/{txid}:0"),
      StatusCode::OK,
      format!(
        ".*<title>Output {txid}:0</title>.*<h1>Output <span class=monospace>{txid}:0</span></h1>
<dl>
  <dt>value</dt><dd>5000000000</dd>
  <dt>script pubkey</dt><dd class=monospace>OP_PUSHBYTES_65 [[:xdigit:]]{{130}} OP_CHECKSIG</dd>
  <dt>transaction</dt><dd><a class=monospace href=/tx/{txid}>{txid}</a></dd>
</dl>.*"
      ),
    );
  }

  #[test]
  fn null_output_is_initially_empty() {
    let txid = "0000000000000000000000000000000000000000000000000000000000000000";
    TestServer::new_with_sat_index().assert_response_regex(
      format!("/output/{txid}:4294967295"),
      StatusCode::OK,
      format!(
        ".*<title>Output {txid}:4294967295</title>.*<h1>Output <span class=monospace>{txid}:4294967295</span></h1>
<dl>
  <dt>value</dt><dd>0</dd>
  <dt>script pubkey</dt><dd class=monospace></dd>
  <dt>transaction</dt><dd><a class=monospace href=/tx/{txid}>{txid}</a></dd>
</dl>
<h2>0 Sat Ranges</h2>
<ul class=monospace>
</ul>.*"
      ),
    );
  }

  #[test]
  fn null_output_receives_lost_sats() {
    let server = TestServer::new_with_sat_index();

    server.mine_blocks_with_subsidy(1, 0);

    let txid = "0000000000000000000000000000000000000000000000000000000000000000";

    server.assert_response_regex(
      format!("/output/{txid}:4294967295"),
      StatusCode::OK,
      format!(
        ".*<title>Output {txid}:4294967295</title>.*<h1>Output <span class=monospace>{txid}:4294967295</span></h1>
<dl>
  <dt>value</dt><dd>5000000000</dd>
  <dt>script pubkey</dt><dd class=monospace></dd>
  <dt>transaction</dt><dd><a class=monospace href=/tx/{txid}>{txid}</a></dd>
</dl>
<h2>1 Sat Range</h2>
<ul class=monospace>
  <li><a href=/range/5000000000/10000000000 class=uncommon>5000000000–10000000000</a></li>
</ul>.*"
      ),
    );
  }

  #[test]
  fn unbound_output_receives_unbound_inscriptions() {
    let server = TestServer::new_with_regtest_with_index_sats();

    server.mine_blocks(1);

    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      fee: 50 * 100_000_000,
      ..Default::default()
    });

    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        2,
        1,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..Default::default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{}", inscription_id),
      StatusCode::OK,
      format!(
        ".*<dl>
  <dt>id</dt>
  <dd class=monospace>{inscription_id}</dd>.*<dt>output</dt>
  <dd><a class=monospace href=/output/0000000000000000000000000000000000000000000000000000000000000000:0>0000000000000000000000000000000000000000000000000000000000000000:0</a></dd>.*"
      ),
    );

    server.assert_response_regex(
      "/output/0000000000000000000000000000000000000000000000000000000000000000:0",
      StatusCode::OK,
      ".*<h1>Output <span class=monospace>0000000000000000000000000000000000000000000000000000000000000000:0</span></h1>
<dl>
  <dt>inscriptions</dt>
  <dd class=thumbnails>
    <a href=/inscription/.*><iframe sandbox=allow-scripts scrolling=no loading=lazy src=/preview/.*></iframe></a>
  </dd>.*",
    );
  }

  #[test]
  fn unbound_output_returns_200() {
    TestServer::new().assert_response_regex(
      "/output/0000000000000000000000000000000000000000000000000000000000000000:0",
      StatusCode::OK,
      ".*",
    );
  }

  #[test]
  fn invalid_output_returns_400() {
    TestServer::new().assert_response(
      "/output/foo:0",
      StatusCode::BAD_REQUEST,
      "Invalid URL: error parsing TXID",
    );
  }

  #[test]
  fn home() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(1);

    let mut ids = Vec::new();

    for i in 0..101 {
      let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("image/png", "hello").to_witness())],
        ..Default::default()
      });
      ids.push(InscriptionId { txid, index: 0 });
      server.mine_blocks(1);
    }

    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "{}").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      "/",
      StatusCode::OK,
      format!(
        r".*<title>Ordinals</title>.*
<h1>Latest Inscriptions</h1>
<div class=thumbnails>
  <a href=/inscription/{}>.*</a>
  (<a href=/inscription/[[:xdigit:]]{{64}}i0>.*</a>\s*){{99}}
</div>
.*
",
        ids[100]
      ),
    );
  }

  #[test]
  fn blocks() {
    let test_server = TestServer::new();

    test_server.mine_blocks(1);

    test_server.assert_response_regex(
      "/blocks",
      StatusCode::OK,
      ".*<title>Blocks</title>.*
<h1>Blocks</h1>
<div class=block>
  <h2><a href=/block/1>Block 1</a></h2>
  <div class=thumbnails>
  </div>
</div>
<div class=block>
  <h2><a href=/block/0>Block 0</a></h2>
  <div class=thumbnails>
  </div>
</div>
</ol>.*",
    );
  }

  #[test]
  fn nav_displays_chain() {
    TestServer::new_with_regtest().assert_response_regex(
      "/",
      StatusCode::OK,
      ".*<a href=/ title=home>Ordinals<sup>regtest</sup></a>.*",
    );
  }

  #[test]
  fn blocks_block_limit() {
    let test_server = TestServer::new();

    test_server.mine_blocks(101);

    test_server.assert_response_regex(
      "/blocks",
      StatusCode::OK,
      ".*<ol start=96 reversed class=block-list>\n(  <li><a href=/block/[[:xdigit:]]{64}>[[:xdigit:]]{64}</a></li>\n){95}</ol>.*"
    );
  }

  #[test]
  fn block_not_found() {
    TestServer::new().assert_response(
      "/block/467a86f0642b1d284376d13a98ef58310caa49502b0f9a560ee222e0a122fe16",
      StatusCode::NOT_FOUND,
      "block 467a86f0642b1d284376d13a98ef58310caa49502b0f9a560ee222e0a122fe16 not found",
    );
  }

  #[test]
  fn unmined_sat() {
    TestServer::new().assert_response_regex(
      "/sat/0",
      StatusCode::OK,
      ".*<dt>timestamp</dt><dd><time>2009-01-03 18:15:05 UTC</time></dd>.*",
    );
  }

  #[test]
  fn mined_sat() {
    TestServer::new().assert_response_regex(
      "/sat/5000000000",
      StatusCode::OK,
      ".*<dt>timestamp</dt><dd><time>.*</time> \\(expected\\)</dd>.*",
    );
  }

  #[test]
  fn static_asset() {
    TestServer::new().assert_response_regex(
      "/static/index.css",
      StatusCode::OK,
      r".*\.rare \{
  background-color: var\(--rare\);
}.*",
    );
  }

  #[test]
  fn favicon() {
    TestServer::new().assert_response_regex("/favicon.ico", StatusCode::OK, r".*");
  }

  #[test]
  fn clock_updates() {
    let test_server = TestServer::new();
    test_server.assert_response_regex("/clock", StatusCode::OK, ".*<text.*>0</text>.*");
    test_server.mine_blocks(1);
    test_server.assert_response_regex("/clock", StatusCode::OK, ".*<text.*>1</text>.*");
  }

  #[test]
  fn block_by_hash() {
    let test_server = TestServer::new();

    test_server.mine_blocks(1);
    let transaction = TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      fee: 0,
      ..Default::default()
    };
    test_server.bitcoin_rpc_server.broadcast_tx(transaction);
    let block_hash = test_server.mine_blocks(1)[0].block_hash();

    test_server.assert_response_regex(
      format!("/block/{block_hash}"),
      StatusCode::OK,
      ".*<h1>Block 2</h1>.*",
    );
  }

  #[test]
  fn block_by_height() {
    let test_server = TestServer::new();

    test_server.assert_response_regex("/block/0", StatusCode::OK, ".*<h1>Block 0</h1>.*");
  }

  #[test]
  fn transaction() {
    let test_server = TestServer::new();

    let coinbase_tx = test_server.mine_blocks(1)[0].txdata[0].clone();
    let txid = coinbase_tx.txid();

    test_server.assert_response_regex(
      format!("/tx/{txid}"),
      StatusCode::OK,
      format!(
        ".*<title>Transaction {txid}</title>.*<h1>Transaction <span class=monospace>{txid}</span></h1>
<dl>
</dl>
<h2>1 Input</h2>
<ul>
  <li><a class=monospace href=/output/0000000000000000000000000000000000000000000000000000000000000000:4294967295>0000000000000000000000000000000000000000000000000000000000000000:4294967295</a></li>
</ul>
<h2>1 Output</h2>
<ul class=monospace>
  <li>
    <a href=/output/84aca0d43f45ac753d4744f40b2f54edec3a496b298951735d450e601386089d:0 class=monospace>
      84aca0d43f45ac753d4744f40b2f54edec3a496b298951735d450e601386089d:0
    </a>
    <dl>
      <dt>value</dt><dd>5000000000</dd>
      <dt>script pubkey</dt><dd class=monospace></dd>
    </dl>
  </li>
</ul>.*"
      ),
    );
  }

  #[test]
  fn detect_unrecoverable_reorg() {
    let test_server = TestServer::new();

    test_server.mine_blocks(21);

    test_server.assert_response_regex(
      "/status",
      StatusCode::OK,
      ".*<dt>unrecoverably reorged</dt>\n  <dd>false</dd>.*",
    );

    for _ in 0..15 {
      test_server.bitcoin_rpc_server.invalidate_tip();
    }

    test_server.bitcoin_rpc_server.mine_blocks(21);

    test_server.assert_response_regex(
      "/status",
      StatusCode::OK,
      ".*<dt>unrecoverably reorged</dt>\n  <dd>true</dd>.*",
    );
  }

  #[test]
  fn rare_with_sat_index() {
    TestServer::new_with_sat_index().assert_response(
      "/rare.txt",
      StatusCode::OK,
      "sat\tsatpoint
0\t4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0
",
    );
  }

  #[test]
  fn rare_without_sat_index() {
    TestServer::new().assert_response(
      "/rare.txt",
      StatusCode::OK,
      "sat\tsatpoint
",
    );
  }

  #[test]
  fn show_rare_txt_in_header_with_sat_index() {
    TestServer::new_with_sat_index().assert_response_regex(
      "/",
      StatusCode::OK,
      ".*
      <a href=/clock title=clock>.*</a>
      <a href=/rare.txt title=rare>.*</a>.*",
    );
  }

  #[test]
  fn rare_sat_location() {
    TestServer::new_with_sat_index().assert_response_regex(
      "/sat/0",
      StatusCode::OK,
      ".*>4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0<.*",
    );
  }

  #[test]
  fn dont_show_rare_txt_in_header_without_sat_index() {
    TestServer::new().assert_response_regex(
      "/",
      StatusCode::OK,
      ".*
      <a href=/clock title=clock>.*</a>
      <a href=https://docs.ordinals.com/.*",
    );
  }

  #[test]
  fn input() {
    TestServer::new().assert_response_regex(
      "/input/0/0/0",
      StatusCode::OK,
      ".*<title>Input /0/0/0</title>.*<h1>Input /0/0/0</h1>.*<dt>text</dt><dd>.*The Times 03/Jan/2009 Chancellor on brink of second bailout for banks</dd>.*",
    );
  }

  #[test]
  fn input_missing() {
    TestServer::new().assert_response(
      "/input/1/1/1",
      StatusCode::NOT_FOUND,
      "input /1/1/1 not found",
    );
  }

  #[test]
  fn commits_are_tracked() {
    let server = TestServer::new();

    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.index.statistic(crate::index::Statistic::Commits), 1);

    let info = server.index.info().unwrap();
    assert_eq!(info.transactions.len(), 1);
    assert_eq!(info.transactions[0].starting_block_count, 0);

    server.index.update().unwrap();

    assert_eq!(server.index.statistic(crate::index::Statistic::Commits), 1);

    let info = server.index.info().unwrap();
    assert_eq!(info.transactions.len(), 1);
    assert_eq!(info.transactions[0].starting_block_count, 0);

    server.mine_blocks(1);

    thread::sleep(Duration::from_millis(10));
    server.index.update().unwrap();

    assert_eq!(server.index.statistic(crate::index::Statistic::Commits), 2);

    let info = server.index.info().unwrap();
    assert_eq!(info.transactions.len(), 2);
    assert_eq!(info.transactions[0].starting_block_count, 0);
    assert_eq!(info.transactions[1].starting_block_count, 1);
    assert!(
      info.transactions[1].starting_timestamp - info.transactions[0].starting_timestamp >= 10
    );
  }

  #[test]
  fn outputs_traversed_are_tracked() {
    let server = TestServer::new_with_sat_index();

    assert_eq!(
      server
        .index
        .statistic(crate::index::Statistic::OutputsTraversed),
      1
    );

    server.index.update().unwrap();

    assert_eq!(
      server
        .index
        .statistic(crate::index::Statistic::OutputsTraversed),
      1
    );

    server.mine_blocks(2);

    server.index.update().unwrap();

    assert_eq!(
      server
        .index
        .statistic(crate::index::Statistic::OutputsTraversed),
      3
    );
  }

  #[test]
  fn coinbase_sat_ranges_are_tracked() {
    let server = TestServer::new_with_sat_index();

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      1
    );

    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      2
    );

    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      3
    );
  }

  #[test]
  fn split_sat_ranges_are_tracked() {
    let server = TestServer::new_with_sat_index();

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      1
    );

    server.mine_blocks(1);
    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      outputs: 2,
      fee: 0,
      ..Default::default()
    });
    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      4,
    );
  }

  #[test]
  fn fee_sat_ranges_are_tracked() {
    let server = TestServer::new_with_sat_index();

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      1
    );

    server.mine_blocks(1);
    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      outputs: 2,
      fee: 2,
      ..Default::default()
    });
    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      5,
    );
  }

  #[test]
  fn content_response_no_content() {
    assert_eq!(
      Server::content_response(
        Inscription::new(Some("text/plain".as_bytes().to_vec()), None),
        AcceptEncoding::default(),
        &ServerConfig::default(),
      )
      .unwrap(),
      None
    );
  }

  #[test]
  fn content_response_with_content() {
    let (headers, body) = Server::content_response(
      Inscription::new(Some("text/plain".as_bytes().to_vec()), Some(vec![1, 2, 3])),
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-type"], "text/plain");
    assert_eq!(body, vec![1, 2, 3]);
  }

  #[test]
  fn content_security_policy_no_origin() {
    let (headers, _) = Server::content_response(
      Inscription::new(Some("text/plain".as_bytes().to_vec()), Some(vec![1, 2, 3])),
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(
      headers["content-security-policy"],
      HeaderValue::from_static("default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:")
    );
  }

  #[test]
  fn content_security_policy_with_origin() {
    let (headers, _) = Server::content_response(
      Inscription::new(Some("text/plain".as_bytes().to_vec()), Some(vec![1, 2, 3])),
      AcceptEncoding::default(),
      &ServerConfig {
        csp_origin: Some("https://ordinals.com".into()),
        ..Default::default()
      },
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-security-policy"], HeaderValue::from_static("default-src https://ordinals.com/content/ https://ordinals.com/blockheight https://ordinals.com/blockhash https://ordinals.com/blockhash/ https://ordinals.com/blocktime https://ordinals.com/r/ 'unsafe-eval' 'unsafe-inline' data: blob:"));
  }

  #[test]
  fn code_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/javascript", "hello").to_witness(),
      )],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<html lang=en data-inscription={inscription_id} data-language=javascript>.*"),
    );
  }

  #[test]
  fn content_response_no_content_type() {
    let (headers, body) = Server::content_response(
      Inscription::new(None, Some(Vec::new())),
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-type"], "application/octet-stream");
    assert!(body.is_empty());
  }

  #[test]
  fn content_response_bad_content_type() {
    let (headers, body) = Server::content_response(
      Inscription::new(Some("\n".as_bytes().to_vec()), Some(Vec::new())),
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-type"], "application/octet-stream");
    assert!(body.is_empty());
  }

  #[test]
  fn text_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..Default::default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{}", inscription_id),
      StatusCode::OK,
      "default-src 'self'",
      format!(".*<html lang=en data-inscription={}>.*", inscription_id),
    );
  }

  #[test]
  fn audio_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("audio/flac", "hello").to_witness())],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<audio .*>\s*<source src=/content/{inscription_id}>.*"),
    );
  }

  #[test]
  fn font_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("font/ttf", "hello").to_witness())],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*src: url\(/content/{inscription_id}\).*"),
    );
  }

  #[test]
  fn pdf_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("application/pdf", "hello").to_witness(),
      )],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<canvas data-inscription={inscription_id}></canvas>.*"),
    );
  }

  #[test]
  fn markdown_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/markdown", "hello").to_witness())],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<html lang=en data-inscription={inscription_id}>.*"),
    );
  }

  #[test]
  fn image_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("image/png", "hello").to_witness())],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      "default-src 'self' 'unsafe-inline'",
      format!(r".*background-image: url\(/content/{inscription_id}\);.*"),
    );
  }

  #[test]
  fn iframe_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/html;charset=utf-8", "hello").to_witness(),
      )],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      "default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:",
      "hello",
    );
  }

  #[test]
  fn unknown_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      "default-src 'self'",
      fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn video_preview() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("video/webm", "hello").to_witness())],
      ..Default::default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<video .*>\s*<source src=/content/{inscription_id}>.*"),
    );
  }

  #[test]
  fn inscription_page_title() {
    let server = TestServer::new_with_regtest_with_index_sats();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      ".*<title>Inscription 0</title>.*",
    );
  }

  #[test]
  fn inscription_page_has_sat_when_sats_are_tracked() {
    let server = TestServer::new_with_regtest_with_index_sats();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      r".*<dt>sat</dt>\s*<dd><a href=/sat/5000000000>5000000000</a></dd>\s*<dt>preview</dt>.*",
    );
  }

  #[test]
  fn inscription_page_does_not_have_sat_when_sats_are_not_tracked() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      r".*<dt>output value</dt>\s*<dd>5000000000</dd>\s*<dt>preview</dt>.*",
    );
  }

  #[test]
  fn strict_transport_security_header_is_set() {
    assert_eq!(
      TestServer::new()
        .get("/status")
        .headers()
        .get(header::STRICT_TRANSPORT_SECURITY)
        .unwrap(),
      "max-age=31536000; includeSubDomains; preload",
    );
  }

  #[test]
  fn feed() {
    let server = TestServer::new_with_regtest_with_index_sats();
    server.mine_blocks(1);

    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      "/feed.xml",
      StatusCode::OK,
      ".*<title>Inscription 0</title>.*",
    );
  }

  #[test]
  fn inscription_with_unknown_type_and_no_body_has_unknown_preview() {
    let server = TestServer::new_with_regtest_with_index_sats();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        Inscription::new(Some("foo/bar".as_bytes().to_vec()), None).to_witness(),
      )],
      ..Default::default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      &fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn inscription_with_known_type_and_no_body_has_unknown_preview() {
    let server = TestServer::new_with_regtest_with_index_sats();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        Inscription::new(Some("image/png".as_bytes().to_vec()), None).to_witness(),
      )],
      ..Default::default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      &fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn content_responses_have_cache_control_headers() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let response = server.get(format!("/content/{}", InscriptionId { txid, index: 0 }));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.headers().get(header::CACHE_CONTROL).unwrap(),
      "public, max-age=31536000, immutable"
    );
  }

  #[test]
  fn error_content_responses_have_max_age_zero_cache_control_headers() {
    let server = TestServer::new_with_regtest();
    let response =
      server.get("/content/6ac5cacb768794f4fd7a78bf00f2074891fce68bd65c4ff36e77177237aacacai0");

    assert_eq!(response.status(), 404);
    assert_eq!(
      response.headers().get(header::CACHE_CONTROL).unwrap(),
      "no-store"
    );
  }

  #[test]
  fn inscriptions_page_with_no_prev_or_next() {
    TestServer::new_with_regtest_with_index_sats().assert_response_regex(
      "/inscriptions",
      StatusCode::OK,
      ".*prev\nnext.*",
    );
  }

  #[test]
  fn inscriptions_page_with_no_next() {
    let server = TestServer::new_with_regtest_with_index_sats();

    for i in 0..101 {
      server.mine_blocks(1);
      server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("text/foo", "hello").to_witness())],
        ..Default::default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/inscriptions/1",
      StatusCode::OK,
      ".*<a class=prev href=/inscriptions/0>prev</a>\nnext.*",
    );
  }

  #[test]
  fn inscriptions_page_with_no_prev() {
    let server = TestServer::new_with_regtest_with_index_sats();

    for i in 0..101 {
      server.mine_blocks(1);
      server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("text/foo", "hello").to_witness())],
        ..Default::default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/inscriptions/0",
      StatusCode::OK,
      ".*prev\n<a class=next href=/inscriptions/1>next</a>.*",
    );
  }

  #[test]
  fn collections_page_prev_and_next() {
    let server = TestServer::new_with_regtest_with_index_sats();

    let mut parent_ids = Vec::new();

    for i in 0..101 {
      server.mine_blocks(1);

      parent_ids.push(InscriptionId {
        txid: server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
          inputs: &[(i + 1, 0, 0, inscription("text/plain", "hello").to_witness())],
          ..Default::default()
        }),
        index: 0,
      });
    }

    for (i, parent_id) in parent_ids.iter().enumerate().take(101) {
      server.mine_blocks(1);

      server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
        inputs: &[
          (i + 2, 1, 0, Default::default()),
          (
            i + 102,
            0,
            0,
            Inscription {
              content_type: Some("text/plain".into()),
              body: Some("hello".into()),
              parent: Some(parent_id.value()),
              ..Default::default()
            }
            .to_witness(),
          ),
        ],
        outputs: 2,
        output_values: &[50 * COIN_VALUE, 50 * COIN_VALUE],
        ..Default::default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/collections",
      StatusCode::OK,
      r".*
<h1>Collections</h1>
<div class=thumbnails>
  <a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>
  (<a href=/inscription/[[:xdigit:]]{64}i0>.*</a>\s*){99}
</div>
<div class=center>
prev
<a class=next href=/collections/1>next</a>
</div>.*"
        .to_string()
        .unindent(),
    );

    server.assert_response_regex(
      "/collections/1",
      StatusCode::OK,
      ".*
<h1>Collections</h1>
<div class=thumbnails>
  <a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>
</div>
<div class=center>
<a class=prev href=/collections/0>prev</a>
next
</div>.*"
        .unindent(),
    );
  }

  #[test]
  fn responses_are_gzipped() {
    let server = TestServer::new();

    let mut headers = HeaderMap::new();

    headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

    let response = reqwest::blocking::Client::builder()
      .default_headers(headers)
      .build()
      .unwrap()
      .get(server.join_url("/"))
      .send()
      .unwrap();

    assert_eq!(
      response.headers().get(header::CONTENT_ENCODING).unwrap(),
      "gzip"
    );
  }

  #[test]
  fn responses_are_brotlied() {
    let server = TestServer::new();

    let mut headers = HeaderMap::new();

    headers.insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

    let response = reqwest::blocking::Client::builder()
      .default_headers(headers)
      .brotli(false)
      .build()
      .unwrap()
      .get(server.join_url("/"))
      .send()
      .unwrap();

    assert_eq!(
      response.headers().get(header::CONTENT_ENCODING).unwrap(),
      "br"
    );
  }

  #[test]
  fn inscriptions_can_be_hidden_with_config() {
    let bitcoin_rpc_server = test_bitcoincore_rpc::spawn();
    bitcoin_rpc_server.mine_blocks(1);
    let txid = bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..Default::default()
    });
    let inscription = InscriptionId { txid, index: 0 };
    bitcoin_rpc_server.mine_blocks(1);

    let server = TestServer::new_with_bitcoin_rpc_server_and_config(
      bitcoin_rpc_server,
      format!("\"hidden\":\n - {inscription}"),
    );

    server.assert_response(
      format!("/preview/{inscription}"),
      StatusCode::OK,
      &fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );

    server.assert_response(
      format!("/content/{inscription}"),
      StatusCode::OK,
      &fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn inscription_links_to_parent() {
    let server = TestServer::new_with_regtest_with_json_api();
    server.mine_blocks(1);

    let parent_txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..Default::default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription 1</title>.*<dt>parent</dt>.*<dd><a class=monospace href=/inscription/{parent_inscription_id}>{parent_inscription_id}</a></dd>.*"),
    );

    server.assert_response_regex(
      format!("/inscription/{parent_inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription 0</title>.*<dt>children</dt>.*<a href=/inscription/{inscription_id}>.*</a>.*"),
    );

    assert_eq!(
      server
        .get_json::<InscriptionJson>(format!("/inscription/{inscription_id}"))
        .parent,
      Some(parent_inscription_id),
    );

    assert_eq!(
      server
        .get_json::<InscriptionJson>(format!("/inscription/{parent_inscription_id}"))
        .children,
      [inscription_id],
    );
  }

  #[test]
  fn inscription_with_and_without_children_page() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let parent_txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    server.assert_response_regex(
      format!("/children/{parent_inscription_id}"),
      StatusCode::OK,
      ".*<h3>No children</h3>.*",
    );

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..Default::default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/children/{parent_inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription 0 Children</title>.*<h1><a href=/inscription/{parent_inscription_id}>Inscription 0</a> Children</h1>.*<div class=thumbnails>.*<a href=/inscription/{inscription_id}><iframe .* src=/preview/{inscription_id}></iframe></a>.*"),
    );
  }

  #[test]
  fn inscriptions_page_shows_max_four_children() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(1);

    let parent_txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(6);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    let _txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (
          3,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (
          4,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (
          5,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (
          6,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parent: Some(parent_inscription_id.value()),
            ..Default::default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..Default::default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{parent_inscription_id}"),
      StatusCode::OK,
      format!(
        ".*<title>Inscription 0</title>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
    <div class=center>
      <a href=/children/{parent_inscription_id}>all</a>
    </div>.*"
      ),
    );
  }

  #[test]
  fn inscription_number_endpoint() {
    let server = TestServer::new_with_regtest();
    server.mine_blocks(2);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, inscription("text/plain", "hello").to_witness()),
        (2, 0, 0, inscription("text/plain", "cursed").to_witness()),
      ],
      outputs: 2,
      ..Default::default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };
    let cursed_inscription_id = InscriptionId { txid, index: 1 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{inscription_id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{inscription_id}</dd>.*"
      ),
    );
    server.assert_response_regex(
      "/inscription/0",
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{inscription_id}</dd>.*"
      ),
    );

    server.assert_response_regex(
      "/inscription/-1",
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{cursed_inscription_id}</dd>.*"
      ),
    )
  }

  #[test]
  fn charm_cursed() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(2);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, Witness::default()),
        (2, 0, 0, inscription("text/plain", "cursed").to_witness()),
      ],
      outputs: 2,
      ..Default::default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=cursed>👹</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_coin() {
    let server = TestServer::new_with_regtest_with_index_sats();

    server.mine_blocks(2);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..Default::default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>.*<span title=coin>🪙</span>.*</dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_uncommon() {
    let server = TestServer::new_with_regtest_with_index_sats();

    server.mine_blocks(2);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..Default::default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>.*<span title=uncommon>🌱</span>.*</dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_nineball() {
    let server = TestServer::new_with_regtest_with_index_sats();

    server.mine_blocks(9);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(9, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..Default::default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>.*<span title=nineball>9️⃣</span>.*</dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_reinscription() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(1);

    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 1, 0, inscription("text/plain", "bar").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_reinscription_in_same_tx_input() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(1);

    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"foo")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"bar")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"qix")
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    let witness = Witness::from_slice(&[script.into_bytes(), Vec::new()]);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, witness)],
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>output value</dt>
  .*
</dl>
.*
"
      ),
    );

    let id = InscriptionId { txid, index: 1 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>.*",
    );

    let id = InscriptionId { txid, index: 2 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>.*",
    );
  }

  #[test]
  fn charm_reinscription_in_same_tx_with_pointer() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(3);

    let cursed_inscription = inscription("text/plain", "bar");
    let reinscription: Inscription = InscriptionTemplate {
      pointer: Some(0),
      ..Default::default()
    }
    .into();

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, inscription("text/plain", "foo").to_witness()),
        (2, 0, 0, cursed_inscription.to_witness()),
        (3, 0, 0, reinscription.to_witness()),
      ],
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>output value</dt>
  .*
</dl>
.*
"
      ),
    );

    let id = InscriptionId { txid, index: 1 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=cursed>👹</span>.*",
    );

    let id = InscriptionId { txid, index: 2 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>.*",
    );
  }

  #[test]
  fn charm_unbound() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, envelope(&[b"ord", &[128], &[0]]))],
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=cursed>👹</span>
    <span title=unbound>🔓</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_lost() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..Default::default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>output value</dt>
  <dd>5000000000</dd>
  .*
</dl>
.*
"
      ),
    );

    server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 1, 0, Default::default())],
      fee: 50 * COIN_VALUE,
      ..Default::default()
    });

    server.mine_blocks_with_subsidy(1, 0);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=monospace>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=lost>🤔</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn sat_recursive_endpoints() {
    let server = TestServer::new_with_regtest_with_index_sats();

    assert_eq!(
      server.get_json::<SatInscriptionsJson>("/r/sat/5000000000"),
      SatInscriptionsJson {
        ids: vec![],
        page: 0,
        more: false
      }
    );

    assert_eq!(
      server.get_json::<SatInscriptionJson>("/r/sat/5000000000/at/0"),
      SatInscriptionJson { id: None }
    );

    server.mine_blocks(1);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let mut ids = Vec::new();
    ids.push(InscriptionId { txid, index: 0 });

    for i in 1..111 {
      let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 1, 0, inscription("text/plain", "foo").to_witness())],
        ..Default::default()
      });

      server.mine_blocks(1);

      ids.push(InscriptionId { txid, index: 0 });
    }

    let paginated_response = server.get_json::<SatInscriptionsJson>("/r/sat/5000000000");

    let equivalent_paginated_response =
      server.get_json::<SatInscriptionsJson>("/r/sat/5000000000/0");

    assert_eq!(paginated_response.ids.len(), 100);
    assert!(paginated_response.more);
    assert_eq!(paginated_response.page, 0);

    assert_eq!(
      paginated_response.ids.len(),
      equivalent_paginated_response.ids.len()
    );
    assert_eq!(paginated_response.more, equivalent_paginated_response.more);
    assert_eq!(paginated_response.page, equivalent_paginated_response.page);

    let paginated_response = server.get_json::<SatInscriptionsJson>("/r/sat/5000000000/1");

    assert_eq!(paginated_response.ids.len(), 11);
    assert!(!paginated_response.more);
    assert_eq!(paginated_response.page, 1);

    assert_eq!(
      server
        .get_json::<SatInscriptionJson>("/r/sat/5000000000/at/0")
        .id,
      Some(ids[0])
    );

    assert_eq!(
      server
        .get_json::<SatInscriptionJson>("/r/sat/5000000000/at/-111")
        .id,
      Some(ids[0])
    );

    assert_eq!(
      server
        .get_json::<SatInscriptionJson>("/r/sat/5000000000/at/110")
        .id,
      Some(ids[110])
    );

    assert_eq!(
      server
        .get_json::<SatInscriptionJson>("/r/sat/5000000000/at/-1")
        .id,
      Some(ids[110])
    );

    assert!(server
      .get_json::<SatInscriptionJson>("/r/sat/5000000000/at/111")
      .id
      .is_none());
  }

  #[test]
  fn children_recursive_endpoint() {
    let server = TestServer::new_with_regtest_with_json_api();
    server.mine_blocks(1);

    let parent_txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..Default::default()
    });

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    server.assert_response(
      format!("/r/children/{parent_inscription_id}"),
      StatusCode::NOT_FOUND,
      &format!("inscription {parent_inscription_id} not found"),
    );

    server.mine_blocks(1);

    let children_json =
      server.get_json::<ChildrenJson>(format!("/r/children/{parent_inscription_id}"));
    assert_eq!(children_json.ids.len(), 0);

    let mut builder = script::Builder::new();
    for _ in 0..111 {
      builder = Inscription {
        content_type: Some("text/plain".into()),
        body: Some("hello".into()),
        parent: Some(parent_inscription_id.value()),
        unrecognized_even_field: false,
        ..Default::default()
      }
      .append_reveal_script_to_builder(builder);
    }

    let witness = Witness::from_slice(&[builder.into_bytes(), Vec::new()]);

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, witness), (2, 1, 0, Default::default())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let first_child_inscription_id = InscriptionId { txid, index: 0 };
    let hundredth_child_inscription_id = InscriptionId { txid, index: 99 };
    let hundred_first_child_inscription_id = InscriptionId { txid, index: 100 };
    let hundred_eleventh_child_inscription_id = InscriptionId { txid, index: 110 };

    let children_json =
      server.get_json::<ChildrenJson>(format!("/r/children/{parent_inscription_id}"));

    assert_eq!(children_json.ids.len(), 100);
    assert_eq!(children_json.ids[0], first_child_inscription_id);
    assert_eq!(children_json.ids[99], hundredth_child_inscription_id);
    assert!(children_json.more);
    assert_eq!(children_json.page, 0);

    let children_json =
      server.get_json::<ChildrenJson>(format!("/r/children/{parent_inscription_id}/1"));

    assert_eq!(children_json.ids.len(), 11);
    assert_eq!(children_json.ids[0], hundred_first_child_inscription_id);
    assert_eq!(children_json.ids[10], hundred_eleventh_child_inscription_id);
    assert!(!children_json.more);
    assert_eq!(children_json.page, 1);
  }

  #[test]
  fn inscriptions_in_block_page() {
    let server = TestServer::new_with_regtest_with_index_sats();

    for _ in 0..101 {
      server.mine_blocks(1);
    }

    for i in 0..101 {
      server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("text/foo", "hello").to_witness())],
        ..Default::default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/inscriptions/block/102",
      StatusCode::OK,
      r".*(<a href=/inscription/[[:xdigit:]]{64}i0>.*</a>.*){100}.*",
    );

    server.assert_response_regex(
      "/inscriptions/block/102/1",
      StatusCode::OK,
      r".*<a href=/inscription/[[:xdigit:]]{64}i0>.*</a>.*",
    );
  }

  #[test]
  fn inscription_query_display() {
    assert_eq!(
      InscriptionQuery::Id(inscription_id(1)).to_string(),
      "1111111111111111111111111111111111111111111111111111111111111111i1"
    );
    assert_eq!(InscriptionQuery::Number(1).to_string(), "1")
  }

  #[test]
  fn inscription_not_found() {
    TestServer::new_with_regtest_with_json_api().assert_response(
      "/inscription/0",
      StatusCode::NOT_FOUND,
      "inscription 0 not found",
    );
  }

  #[test]
  fn delegate() {
    let server = TestServer::new_with_regtest();

    server.mine_blocks(1);

    let delegate = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..Default::default()
    };

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, delegate.to_witness())],
      ..Default::default()
    });

    let delegate = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    let inscription = Inscription {
      delegate: Some(delegate.value()),
      ..Default::default()
    };

    let txid = server.bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, inscription.to_witness())],
      ..Default::default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 1</h1>.*
        <dl>
          <dt>id</dt>
          <dd class=monospace>{id}</dd>
          .*
          <dt>delegate</dt>
          <dd><a href=/inscription/{delegate}>{delegate}</a></dd>
          .*
        </dl>.*"
      )
      .unindent(),
    );

    server.assert_response(format!("/content/{id}"), StatusCode::OK, "foo");

    server.assert_response(format!("/preview/{id}"), StatusCode::OK, "foo");
  }
}
