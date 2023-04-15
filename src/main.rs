use actix::*;
use actix_web::http::StatusCode;
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use expanduser::expanduser;
use std::collections::{HashMap, HashSet};

use actix_web::rt::time::sleep;
use std::time::Duration;

use std::sync::{Arc, RwLock};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use anyhow::Context;

use ulid::Ulid;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub basedir: String,
    pub metadata_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct CacheRequest {
    pub simulation: String,
    pub snapshot_id: usize,
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            basedir: expanduser("~/Documents/data/tng/manual_download/")
                .expect("Failed to expand user.")
                .display()
                .to_string(),
            metadata_url: "http://localhost:9999".to_string(),
        }
    }
}

#[derive(Clone)]
struct Metadata {
    snap_to_cache_server: HashMap<String, HashMap<usize, String>>,
    cache_server_to_snap: HashMap<String, Vec<(String, usize)>>,
    known_hosts: HashSet<String>,
}

impl Metadata {
    fn new() -> Self {
        Self {
            snap_to_cache_server: HashMap::new(),
            cache_server_to_snap: HashMap::new(),
            known_hosts: HashSet::new(),
        }
    }

    async fn add_new_host(&mut self, address: &String) -> anyhow::Result<()> {
        let client = Client::new();
        match client
            .get(address.clone() + "/v1/get/current_cache")
            .send()
            .await
        {
            Ok(result) => {
                let cache = result
                    .json::<HashMap<String, Vec<usize>>>()
                    .await
                    .context("Invalid JSON response.")?;
                self.add_cache_server_snaps(address, cache)?;
            }
            Err(err) => {
                log::warn!("Failed to get cache from new cache server {:?}", err);
            }
        };
        self.known_hosts.insert(address.to_string());
        Ok(())
    }

    fn add_cache_server_snaps(
        &mut self,
        address: &String,
        cache: HashMap<String, Vec<usize>>,
    ) -> anyhow::Result<()> {
        for (simulation, snapshot_ids) in cache {
            for snapshot_id in snapshot_ids {
                self.add_snap(&simulation, snapshot_id, address)
                    .context("Tried to add snap from cache bulk.")?;
            }
        }
        Ok(())
    }

    fn add_snap_to_cache_server(
        &mut self,
        simulation: &String,
        snapshot_id: usize,
        address: &String,
    ) -> anyhow::Result<()> {
        match self.snap_to_cache_server.get_mut(simulation) {
            Some(hashmap) => {
                hashmap.insert(snapshot_id, address.to_string());
                return Ok(());
            }
            None => {
                let mut hashmap = HashMap::new();
                hashmap.insert(snapshot_id, address.to_string());
                self.snap_to_cache_server
                    .insert(simulation.to_string(), hashmap);
                return Ok(());
            }
        }
    }

    fn add_cache_server_to_snap(
        &mut self,
        simulation: &String,
        snapshot_id: usize,
        address: &String,
    ) -> anyhow::Result<()> {
        match self.cache_server_to_snap.get_mut(simulation) {
            Some(entries) => {
                entries.push((address.to_string(), snapshot_id));
                return Ok(());
            }
            None => {
                self.cache_server_to_snap.insert(
                    simulation.to_string(),
                    vec![(address.to_string(), snapshot_id)],
                );
                return Ok(());
            }
        }
    }

    fn add_snap(
        &mut self,
        simulation: &String,
        snapshot_id: usize,
        address: &String,
    ) -> anyhow::Result<()> {
        self.add_snap_to_cache_server(simulation, snapshot_id, address)?;
        self.add_cache_server_to_snap(simulation, snapshot_id, address)?;
        Ok(())
    }

    fn remove_cache_server(&mut self, address: String) -> anyhow::Result<()> {
        // Go through all known snaps of this host and remove them
        if let Some(entries) = self.cache_server_to_snap.get(&address) {
            for (simulation, snapshot_id) in entries {
                if let Some(hashmap) = self.snap_to_cache_server.get_mut(simulation) {
                    hashmap.remove(&snapshot_id);
                }
            }
        }

        // Remove the info about the host
        self.cache_server_to_snap.remove(&address);
        Ok(())
    }

    fn find_host_for_snap(&self, simulation: &String, snapshot_id: usize) -> Option<String> {
        self.snap_to_cache_server
            .get(simulation)
            .and_then(|hashmap| {
                hashmap
                    .get(&snapshot_id)
                    .and_then(|address| Some(address.clone()))
            })
    }
}

async fn ping(req: HttpRequest, metadata: web::Data<Arc<RwLock<Metadata>>>) -> impl Responder {
    let address = req
        .headers()
        .get("user-agent")
        .expect("No user agent was provided.")
        .to_str()
        .expect("Failed to generate string.")
        .to_string();
    let contains = {
        let metadata = metadata.read().expect("Failed to aquire read");
        metadata.known_hosts.contains(&address)
    };
    if !contains {
        log::info!("Adding new host.");
        let mut metadata = metadata.write().expect("Failed to aquire write");
        _ = metadata.add_new_host(&address).await.or_else(|_| {
            log::warn!("Failed to add new host");
            Ok::<(), anyhow::Error>(())
        });
    } else {
        log::info!("Host already known.");
    }

    HttpResponse::new(StatusCode::OK)
}

async fn add_snap(
    req: HttpRequest,
    cache_request: web::Json<CacheRequest>,
    metadata: web::Data<Arc<RwLock<Metadata>>>,
) -> impl Responder {
    let address = req
        .headers()
        .get("user-agent")
        .expect("No user agent was provided.")
        .to_str()
        .expect("Failed to generate string.")
        .to_string();

    log::info!("Adding new snap.");
    {
        let mut metadata = metadata.write().expect("Failed to aquire write");
        match metadata.add_snap(
            &cache_request.simulation,
            cache_request.snapshot_id,
            &address,
        ) {
            Ok(_) => {}
            Err(_) => log::warn!("Failed to add snap"),
        }
    }

    HttpResponse::new(StatusCode::OK)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let _cfg: Config = confy::load_path("cfg.yml").expect("Failed to load config from disk");

    let metadata = Arc::new(RwLock::new(Metadata::new()));

    log::info!("starting HTTP server at http://localhost:9999");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(metadata.clone()))
            .route("/ping", web::post().to(ping))
            .route("/add_snap", web::post().to(add_snap))
            .wrap(Logger::default())
    })
    .workers(2)
    .bind(("127.0.0.1", 9999))?
    .run()
    .await
}
