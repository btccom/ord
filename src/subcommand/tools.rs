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
  
  enum InscriptionQuery {
    Id(InscriptionId),
    Number(i32),
  }
  
  impl FromStr for InscriptionQuery {
    type Err = Error;
  
    fn from_str(s: &str) -> Result<Self, Self::Err> {
      Ok(if s.contains('i') {
        InscriptionQuery::Id(s.parse()?)
      } else {
        InscriptionQuery::Number(s.parse()?)
      })
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
      default_value = "0.0.0.0",
      help = "Listen on <ADDRESS> for incoming requests."
    )]
    address: String,
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
      help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]."
    )]
    http_port: Option<u16>,
    #[arg(
      long,
      group = "port",
      help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]."
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
        log::info!(
            "running tools",
          );
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
      let addr = (self.address.as_str(), port)
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
  
    fn acme_cache(acme_cache: Option<&PathBuf>, options: &Options) -> Result<PathBuf> {
      let acme_cache = if let Some(acme_cache) = acme_cache {
        acme_cache.clone()
      } else {
        options.data_dir()?.join("acme-cache")
      };
  
      Ok(acme_cache)
    }
  
    fn acme_domains(&self) -> Result<Vec<String>> {
      if !self.acme_domain.is_empty() {
        Ok(self.acme_domain.clone())
      } else {
        Ok(vec![System::new()
          .host_name()
          .ok_or(anyhow!("no hostname found"))?])
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
        )?)))
        .directory(if cfg!(test) {
          LETS_ENCRYPT_STAGING_DIRECTORY
        } else {
          LETS_ENCRYPT_PRODUCTION_DIRECTORY
        });
  
      let mut state = config.state();
  
      let acceptor = state.axum_acceptor(Arc::new(
        rustls::ServerConfig::builder()
          .with_no_client_auth()
          .with_cert_resolver(state.resolver()),
      ));
  
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
  