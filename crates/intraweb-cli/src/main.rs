//! intraweb -- your neighborhood web.

mod api;
mod channels;
mod guard;
mod http;
mod limits;
mod mail;
mod surf;
mod tui;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use intraweb_core::channel::ChannelId;
use intraweb_core::peer::{Peer, now_secs};
use intraweb_core::{Config, Identity, Runtime, Store, Vault};
use intraweb_net::Node;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "intraweb",
    version,
    about = "your neighborhood web",
    long_about = "A local-first intranet. Your identity is a keypair and one folder; \
                  hubs are places to meet, not servers that own your data."
)]
struct Cli {
    /// Where your vault lives. Defaults to $INTRAWEB_VAULT, then ~/.intraweb
    #[arg(long, global = true, value_name = "DIR")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the node: announce yourself, find neighbors, serve your vault.
    Up(UpArgs),
    /// Diagnose why neighbors are or are not showing up.
    Doctor {
        /// Seconds to listen on both discovery paths.
        #[arg(long, default_value_t = 5)]
        listen: u64,
    },
    /// Publish a folder to the neighborhood without copying it into your vault.
    Serve {
        /// The directory to publish as your site.
        #[arg(value_name = "DIR")]
        dir: PathBuf,

        #[command(flatten)]
        args: UpArgs,
    },
    /// See what your neighbors are publishing.
    Surf {
        /// Seconds to listen for neighbors before asking what they serve.
        #[arg(long, default_value_t = 3)]
        listen: u64,

        /// Open this numbered site in a browser instead of only listing.
        #[arg(long, value_name = "N")]
        open: Option<usize>,
    },
    /// Send and read local mail.
    Mail {
        #[command(subcommand)]
        cmd: Option<MailCmd>,
    },
    /// List the files a neighbor is sharing.
    Ls {
        /// Nickname, fingerprint, or public key.
        peer: String,
    },
    /// Download a file from a neighbor. Interrupted downloads resume.
    Get {
        /// Nickname, fingerprint, or public key.
        peer: String,
        /// Path as shown by `intraweb ls`.
        file: String,
        /// Where to write it. Defaults to the file's own name here.
        #[arg(long, short, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Say something in the neighborhood channel.
    Say {
        /// What to say.
        message: Vec<String>,
        /// Post to a private channel instead, by name or id.
        #[arg(long, short, value_name = "CHANNEL")]
        channel: Option<String>,
    },
    /// Write in a neighbor's guestbook.
    Sign {
        /// Nickname, fingerprint, or public key.
        peer: String,
        /// What to write.
        message: Vec<String>,
    },
    /// Read your own guestbook.
    Guestbook,
    /// Read a channel.
    Chat {
        /// Which channel, by name or id. Defaults to the neighborhood.
        channel: Option<String>,
    },
    /// Make and manage private channels.
    Channel {
        #[command(subcommand)]
        cmd: ChannelCmd,
    },
    /// Refuse to see or hear from somebody.
    Block {
        /// Nickname, fingerprint, or public key.
        peer: String,
        /// A note to yourself about why.
        #[arg(long, short, default_value = "")]
        reason: String,
    },
    /// Undo a block.
    Unblock {
        /// Nickname, fingerprint, or public key.
        peer: String,
    },
    /// List the keys you have blocked.
    Blocked,
    /// Print your identity and where your vault lives.
    Id,
}

#[derive(Subcommand)]
enum ChannelCmd {
    /// Start a private channel. Only people you invite can read it.
    New {
        /// What to call it.
        name: Vec<String>,
    },
    /// Show the channels this vault knows about.
    List,
    /// Let somebody into a private channel. They must be in range.
    Invite {
        /// Channel name or id.
        channel: String,
        /// Nickname, fingerprint, or public key.
        peer: String,
    },
}

#[derive(Subcommand)]
enum MailCmd {
    /// Write to a neighbor. Queues if they are not in range yet.
    Send {
        /// Nickname, fingerprint, or public key.
        to: String,
        #[arg(long, short, default_value = "")]
        subject: String,
        /// The message. Read from stdin when omitted.
        #[arg(long, short)]
        message: Option<String>,
        /// Offer a file from your shared folder, by path. The bytes stay with
        /// you until they fetch them.
        #[arg(long, short = 'a', value_name = "PATH")]
        attach: Option<String>,
    },
    /// Show what you have received.
    Inbox,
    /// Show what you have sent, and what is still waiting.
    Outbox,
    /// Reply to a message, by the number shown in the inbox.
    Reply {
        id: i64,
        #[arg(long, short)]
        message: Option<String>,
    },
    /// Throw a message away.
    Delete { id: i64 },
}

#[derive(Args)]
struct UpArgs {
    /// Host a hub: claim intranet.local and be a meeting point for the network.
    #[arg(long)]
    hub: bool,

    /// Name shown for the hub you are hosting.
    #[arg(long, value_name = "NAME")]
    hub_name: Option<String>,

    /// Display name. Your key stays the same whatever you call yourself.
    #[arg(long, value_name = "NAME")]
    nickname: Option<String>,

    /// Port for the dashboard and JSON API.
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    /// Show the terminal dashboard instead of log output.
    #[arg(long)]
    tui: bool,

    /// Turn off UDP broadcast and rely on mDNS alone.
    #[arg(long)]
    no_beacon: bool,

    /// Publish this folder instead of the vault's own site/ directory.
    #[arg(long, value_name = "DIR")]
    site: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    // Print the error chain rather than a Debug backtrace: "no neighbor matches
    // that name" is an ordinary outcome, not a crash report.
    if let Err(err) = run().await {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let vault = Vault::resolve(cli.vault)?;

    match cli.command.unwrap_or(Command::Up(UpArgs {
        hub: false,
        hub_name: None,
        nickname: None,
        port: None,
        tui: false,
        no_beacon: false,
        site: None,
    })) {
        Command::Up(args) => up(vault, args).await,
        Command::Serve { dir, mut args } => {
            args.site = Some(dir);
            up(vault, args).await
        }
        Command::Surf { listen, open } => surf_command(vault, listen, open).await,
        Command::Mail { cmd } => mail_command(vault, cmd.unwrap_or(MailCmd::Inbox)).await,
        Command::Ls { peer } => ls_command(vault, &peer).await,
        Command::Block { peer, reason } => block_command(vault, &peer, &reason).await,
        Command::Unblock { peer } => unblock_command(vault, &peer).await,
        Command::Blocked => blocked_command(vault),
        Command::Say { message, channel } => {
            say_command(vault, &message.join(" "), channel.as_deref()).await
        }
        Command::Chat { channel } => chat_command(vault, channel.as_deref()),
        Command::Sign { peer, message } => sign_command(vault, &peer, &message.join(" ")).await,
        Command::Guestbook => guestbook_command(vault),
        Command::Channel { cmd } => channel_command(vault, cmd).await,
        Command::Get { peer, file, output } => get_command(vault, &peer, &file, output).await,
        Command::Doctor { listen } => doctor(vault, listen).await,
        Command::Id => show_id(vault),
    }
}

/// Prepare the vault: create the layout, load or mint the identity, read config.
fn open_vault(vault: &Vault) -> Result<(Arc<Identity>, Config, bool)> {
    vault.ensure()?;
    let (identity, minted) = Identity::load_or_create(&vault.identity_path())?;
    let config = Config::load_or_create(&vault.config_path())?;
    Ok((Arc::new(identity), config, minted))
}

async fn up(vault: Vault, args: UpArgs) -> Result<()> {
    if !args.tui {
        init_logging();
    }

    let (identity, mut config, minted) = open_vault(&vault)?;

    // Flags win over the stored config, but are not written back: a one-off
    // `--hub` should not silently turn this node into a hub forever.
    if args.hub {
        config.hub = true;
    }
    if let Some(name) = args.hub_name {
        config.hub_name = name;
    }
    if let Some(nickname) = args.nickname {
        config.nickname = nickname;
    }
    // Remember that the operator picked this, so the hub's port-80 preference
    // does not quietly move the dashboard out from under them.
    let port_was_chosen =
        args.port.is_some() || config.api_port != intraweb_core::config::DEFAULT_API_PORT;
    if let Some(port) = args.port {
        config.api_port = port;
    }
    if args.no_beacon {
        config.beacon_enabled = false;
    }

    // A served folder is published in place; nothing is copied into the vault,
    // so pointing at a directory never disturbs what you normally publish.
    let site_dir = match &args.site {
        Some(dir) => {
            let dir = dir.canonicalize().with_context(|| {
                format!("could not find the folder to serve: {}", dir.display())
            })?;
            anyhow::ensure!(dir.is_dir(), "{} is not a directory", dir.display());
            dir
        }
        None => vault.site_dir(),
    };

    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);
    let vault = Arc::new(vault);

    if minted {
        println!("Minted a new identity: {}", identity.fingerprint());
        println!(
            "Back up {} -- it is your name on every hub.\n",
            vault.root().display()
        );
    }

    channels::ensure_neighborhood(&store)?;
    channels::ensure_guestbook(&store, &identity)?;

    let node = Node::start(&config, Arc::clone(&identity), Arc::clone(&store))
        .context("could not start discovery")?;

    // Anything queued leaves as soon as its recipient turns up. This is the
    // whole of store-and-forward: the sender keeps trying, nobody relays.
    {
        let store = Arc::clone(&store);
        let roster = node.roster.clone();
        let identity = Arc::clone(&identity);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(mail::OUTBOX_INTERVAL_SECS));
            loop {
                ticker.tick().await;
                mail::deliver_pending(&store, &roster, &identity).await;
            }
        });
    }

    let state = api::AppState {
        roster: node.roster.clone(),
        identity: Arc::clone(&identity),
        store: Arc::clone(&store),
        config: Arc::clone(&config),
        vault: Arc::clone(&vault),
        site_dir: site_dir.clone(),
        started_at: now_secs(),
        limiter: Arc::new(limits::RateLimiter::new(limits::now_float())),
    };

    // A hub tries port 80 so newcomers can type a bare hostname -- unless a
    // port was chosen, in which case that one is honored.
    let (listener, port) = api::bind(
        api::should_try_low_port(config.hub, port_was_chosen),
        config.api_port,
    )
    .await?;
    let where_to_go = if config.hub {
        format!("http://intranet.local{}", suffix(port))
    } else {
        format!("http://localhost{}", suffix(port))
    };

    // Tell local commands where to find us, so they need not re-discover.
    Runtime::new(port).save(&vault.runtime_path()).ok();

    if args.tui {
        let dashboard = tui::Dashboard::new(
            node.roster.clone(),
            Arc::clone(&identity),
            Arc::clone(&store),
            Arc::clone(&config),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, api::router(state)).await;
        });
        // The terminal loop blocks, so it gets a thread of its own.
        tokio::task::spawn_blocking(move || dashboard.run()).await??;
        server.abort();
    } else {
        println!("intraweb -- your neighborhood web");
        println!(
            "  you        {} ({})",
            config.sanitized_nickname(),
            identity.fingerprint()
        );
        println!("  vault      {}", vault.root().display());
        println!("  serving    {}", site_dir.display());
        println!("  dashboard  {where_to_go}");
        println!(
            "  your site  {where_to_go}/~{}",
            config.sanitized_nickname()
        );
        if config.hub {
            println!("  hosting    {}", config.hub_name);
        }
        println!("\nListening for neighbors. Ctrl-C to stop.\n");

        let server = axum::serve(listener, api::router(state));
        tokio::select! {
            result = server => result.context("the dashboard stopped unexpectedly")?,
            _ = tokio::signal::ctrl_c() => println!("\nLeaving the neighborhood."),
        }
    }

    node.shutdown();
    Ok(())
}

/// Look around the neighborhood and report what is being published.
///
/// This listens without announcing: looking at what neighbors serve should not
/// change what they see, and it keeps a node already running on this machine
/// from colliding with a second announcement under the same key.
async fn surf_command(vault: Vault, listen: u64, open: Option<usize>) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    let node = Node::observe(&config, Arc::clone(&identity), Arc::clone(&store))
        .context("could not listen for neighbors")?;

    println!("Looking around the neighborhood for {listen}s...");
    tokio::time::sleep(Duration::from_secs(listen)).await;

    let peers = node.roster.peers();
    node.shutdown();

    if peers.is_empty() {
        println!("\nNobody is publishing anything right now.");
        println!("If you expected company, run `intraweb doctor` -- an empty list");
        println!("usually means the access point, not a broken node.");
        return Ok(());
    }

    let sites = surf::survey(peers, surf::PROBE_TIMEOUT).await;
    // Reachable sites first; nothing is more annoying than a listing led by
    // things you cannot open.
    let mut sites = sites;
    sites.sort_by(|a, b| {
        b.reachable
            .cmp(&a.reachable)
            .then_with(|| b.is_hub.cmp(&a.is_hub))
            .then_with(|| a.nickname.cmp(&b.nickname))
    });

    if let Some(choice) = open {
        let Some(site) = choice.checked_sub(1).and_then(|i| sites.get(i)) else {
            anyhow::bail!("there is no site {choice}; run `intraweb surf` to see the list");
        };
        println!("Opening {}", site.url);
        return surf::open_in_browser(&site.url);
    }

    let width = sites
        .iter()
        .map(|s| s.nickname.chars().count())
        .max()
        .unwrap_or(8)
        .max(8);
    println!();
    for (index, site) in sites.iter().enumerate() {
        let marker = if site.is_hub { "*" } else { " " };
        println!(
            "{marker} {:>2}  {:<width$}  {:<34}  {}",
            index + 1,
            site.nickname,
            site.describe(),
            site.url,
        );
        // Never let a familiar-looking name stand on its own when the key
        // behind it has changed.
        if let Some(warning) = site.warning() {
            println!("      {:<width$}  !! {warning}", "");
        }
    }

    let unreachable = sites.iter().filter(|s| !s.reachable).count();
    println!();
    if sites.iter().any(|s| s.is_hub) {
        println!("* hub");
    }
    if unreachable > 0 {
        println!(
            "{unreachable} neighbor(s) are announcing but not answering -- they may have just left."
        );
    }
    println!("Open one with: intraweb surf --open <number>");
    Ok(())
}

/// Get the current roster as cheaply as possible.
///
/// If a node is already running here, its dashboard already knows who is about,
/// so ask it rather than spending seconds re-discovering the same network. Only
/// when nothing is running do we listen for ourselves.
async fn peers_now(
    vault: &Vault,
    config: &Arc<Config>,
    identity: &Arc<Identity>,
    store: &Arc<Mutex<Store>>,
    listen: u64,
) -> Result<Vec<Peer>> {
    let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    // A running node publishes the port it really bound; fall back to the
    // configured one and then the clean-URL port a hub would have taken.
    let running = Runtime::load(&vault.runtime_path()).map(|r| r.api_port);
    let candidates: Vec<u16> = running.into_iter().chain([config.api_port, 80]).collect();

    for port in candidates {
        if let Ok(response) = http::get(local, port, "/api/peers", Duration::from_millis(400)).await
            && response.is_success()
            && let Ok(peers) = serde_json::from_str::<Vec<Peer>>(&response.body)
        {
            return Ok(peers);
        }
    }

    let node = Node::observe(config, Arc::clone(identity), Arc::clone(store))
        .context("could not listen for neighbors")?;
    eprintln!("Looking for neighbors for {listen}s...");
    tokio::time::sleep(Duration::from_secs(listen)).await;
    let peers = node.roster.peers();
    node.shutdown();
    Ok(peers)
}

async fn mail_command(vault: Vault, cmd: MailCmd) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    match cmd {
        MailCmd::Send {
            to,
            subject,
            message,
            attach,
        } => {
            let body = match message {
                Some(body) => body,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .context("could not read stdin")?;
                    buf
                }
            };

            let live = peers_now(&vault, &config, &identity, &store, 3).await?;
            let recipient = mail::resolve_or_explain(&mail::addressable(&live, &store), &to)?;

            // Offering a file we do not have would leave the recipient
            // fetching a 404, so check before the message goes anywhere.
            if let Some(path) = attach.as_deref() {
                let full = vault.files_dir().join(path);
                anyhow::ensure!(
                    full.is_file(),
                    "there is no {path} in your shared folder ({})",
                    vault.files_dir().display(),
                );
            }

            let queued_id = mail::queue(
                &store,
                identity.peer_id(),
                recipient.peer_id,
                &subject,
                &body,
                attach.as_deref(),
            )?;

            // Try immediately; a running node keeps retrying if this misses.
            let delivered = {
                let mut outgoing = intraweb_core::Mail::new(
                    identity.peer_id(),
                    recipient.peer_id,
                    &subject,
                    &body,
                    now_secs(),
                );
                if let Some(path) = attach.as_deref() {
                    outgoing = outgoing.with_attachment(path);
                }
                let sealed = intraweb_core::SignedMail::seal(outgoing, &identity)?;
                mail::deliver_one(&recipient, &sealed).await.is_ok()
            };

            if delivered {
                // Mark the row we actually queued; picking "the newest pending"
                // would grab the wrong one if two were queued in the same second.
                if let Ok(store) = store.lock() {
                    store.mark_delivered(queued_id, now_secs()).ok();
                }
                println!(
                    "Delivered to {} ({}).",
                    recipient.nickname, recipient.fingerprint
                );
            } else {
                println!(
                    "Queued for {} ({}). It will go as soon as they are reachable.",
                    recipient.nickname, recipient.fingerprint
                );
            }
            Ok(())
        }

        MailCmd::Inbox => {
            let Ok(store) = store.lock() else {
                anyhow::bail!("the mail store is busy");
            };
            let messages = store.inbox(50)?;
            if messages.is_empty() {
                println!("No mail.");
                return Ok(());
            }
            for message in &messages {
                let unread = if message.read_at.is_none() { "*" } else { " " };
                println!(
                    "{unread} [{}] {}  {}",
                    message.id,
                    message.peer_id.fingerprint(),
                    if message.subject.is_empty() {
                        "(no subject)"
                    } else {
                        &message.subject
                    },
                );
                for line in message.body.lines() {
                    println!("      {line}");
                }
                if let Some(path) = &message.attachment {
                    println!("      attached: {path}");
                    println!(
                        "      fetch it with: intraweb get {} {path}",
                        message.peer_id.fingerprint()
                    );
                }
                println!();
            }
            store.mark_all_read(now_secs())?;
            Ok(())
        }

        MailCmd::Reply { id, message } => {
            let (original, body) = {
                let body = match message {
                    Some(body) => body,
                    None => {
                        use std::io::Read;
                        let mut buf = String::new();
                        std::io::stdin()
                            .read_to_string(&mut buf)
                            .context("could not read stdin")?;
                        buf
                    }
                };
                let store = store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("the mail store is busy"))?;
                let original = store
                    .mail_by_id(id)?
                    .with_context(|| format!("there is no message {id}"))?;
                (original, body)
            };

            let subject = if original.subject.starts_with("re: ") {
                original.subject.clone()
            } else {
                format!("re: {}", original.subject)
            };

            let queued_id = mail::queue(
                &store,
                identity.peer_id(),
                original.peer_id,
                &subject,
                &body,
                None,
            )?;

            // Try now; a running node keeps retrying if this misses.
            let live = peers_now(&vault, &config, &identity, &store, 3).await?;
            let delivered = match live.iter().find(|p| p.peer_id == original.peer_id) {
                Some(peer) => {
                    let sealed = intraweb_core::SignedMail::seal(
                        intraweb_core::Mail::new(
                            identity.peer_id(),
                            original.peer_id,
                            &subject,
                            &body,
                            now_secs(),
                        ),
                        &identity,
                    )?;
                    mail::deliver_one(peer, &sealed).await.is_ok()
                }
                None => false,
            };

            if delivered {
                if let Ok(store) = store.lock() {
                    store.mark_delivered(queued_id, now_secs()).ok();
                }
                println!("Replied to {}.", original.peer_id.fingerprint());
            } else {
                println!("Reply queued for {}.", original.peer_id.fingerprint());
            }
            Ok(())
        }

        MailCmd::Delete { id } => {
            let store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("the mail store is busy"))?;
            if store.delete_mail(id)? {
                println!("Deleted message {id}.");
            } else {
                println!("There is no message {id}.");
            }
            Ok(())
        }

        MailCmd::Outbox => {
            let Ok(store) = store.lock() else {
                anyhow::bail!("the mail store is busy");
            };
            let messages = store.outbox(50)?;
            if messages.is_empty() {
                println!("Nothing sent yet.");
                return Ok(());
            }
            for message in &messages {
                let state = if message.delivered_at.is_some() {
                    "sent  "
                } else {
                    "queued"
                };
                println!(
                    "{state}  {}  {}",
                    message.peer_id.fingerprint(),
                    if message.subject.is_empty() {
                        "(no subject)"
                    } else {
                        &message.subject
                    },
                );
            }
            Ok(())
        }
    }
}

/// Find a channel by name or id, so people can type what they see.
fn resolve_channel(store: &Mutex<Store>, query: Option<&str>) -> Result<ChannelId> {
    let Some(query) = query else {
        return Ok(ChannelId::neighborhood());
    };
    let needle = query.trim().to_lowercase();

    if let Some(channel) = ChannelId::parse_hex(&needle) {
        return Ok(channel);
    }

    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    let channels = store.channels()?;
    let matches: Vec<_> = channels
        .iter()
        .filter(|c| c.name.to_lowercase() == needle || c.channel_id.short().starts_with(&needle))
        .collect();

    match matches.as_slice() {
        [only] => Ok(only.channel_id),
        [] => {
            let names: Vec<&str> = channels.iter().map(|c| c.name.as_str()).collect();
            anyhow::bail!(
                "no channel called {query:?}. You have: {}",
                names.join(", ")
            )
        }
        several => {
            let mut lines = vec![format!("{} channels match {query:?}:", several.len())];
            for channel in several {
                lines.push(format!(
                    "  {}  {}",
                    channel.channel_id.short(),
                    channel.name
                ));
            }
            anyhow::bail!("{}", lines.join("\n"))
        }
    }
}

async fn say_command(vault: Vault, message: &str, channel: Option<&str>) -> Result<()> {
    anyhow::ensure!(!message.trim().is_empty(), "nothing to say");

    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);
    channels::ensure_neighborhood(&store)?;

    let target = resolve_channel(&store, channel)?;

    // Speaking needs to know who is in range, so discovery runs first.
    let live = peers_now(&vault, &config, &identity, &store, 3).await?;
    let delivery = channels::say_to(&store, &identity, &live, target, message).await?;

    if delivery.reached == 0 {
        println!("Said it, but nobody was in range to hear. It is in your own log.");
    } else {
        println!("Said to {} neighbor(s).", delivery.reached);
    }
    if delivery.missed > 0 {
        println!("{} could not be reached.", delivery.missed);
    }
    Ok(())
}

fn chat_command(vault: Vault, channel: Option<&str>) -> Result<()> {
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    channels::ensure_neighborhood(&store)?;
    let target = resolve_channel(&store, channel)?;

    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    let posts = store.posts(target, 60)?;
    if posts.is_empty() {
        println!("Nothing said here yet.");
        return Ok(());
    }
    for post in posts {
        if post.readable {
            println!("{}  {}", post.fingerprint, post.body);
        } else {
            println!(
                "{}  [encrypted -- you are not in this channel]",
                post.fingerprint
            );
        }
    }
    Ok(())
}

async fn sign_command(vault: Vault, query: &str, message: &str) -> Result<()> {
    anyhow::ensure!(!message.trim().is_empty(), "write something to leave");

    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    let live = peers_now(&vault, &config, &identity, &store, 3).await?;
    let owner = mail::resolve_or_explain(&live, query)?;

    channels::sign_guestbook(&store, &identity, &owner, message).await?;

    println!("Signed {}'s guestbook.", owner.nickname);
    Ok(())
}

fn guestbook_command(vault: Vault) -> Result<()> {
    let (identity, _, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    channels::ensure_guestbook(&store, &identity)?;

    let store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("the store is busy"))?;
    let entries = store.posts(ChannelId::guestbook_of(identity.peer_id()), 100)?;
    if entries.is_empty() {
        println!("Nobody has signed your guestbook yet.");
        println!("Neighbors can with: intraweb sign <you> \"...\"");
        return Ok(());
    }
    for entry in entries {
        println!("{}  {}", entry.fingerprint, entry.body);
    }
    Ok(())
}

async fn channel_command(vault: Vault, cmd: ChannelCmd) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);
    channels::ensure_neighborhood(&store)?;

    match cmd {
        ChannelCmd::New { name } => {
            let name = name.join(" ");
            anyhow::ensure!(!name.trim().is_empty(), "give the channel a name");
            let channel = channels::create_private(&store, &identity, &name)?;

            println!("Created {name} ({}).", channel.short());
            println!("Nobody else can read it until you invite them:");
            println!("  intraweb channel invite {name:?} <neighbor>");
            Ok(())
        }
        ChannelCmd::List => {
            let store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("the store is busy"))?;
            for channel in store.channels()? {
                let kind = if channel.is_private {
                    "private"
                } else {
                    "public "
                };
                let note = if channel.can_read {
                    ""
                } else {
                    "  (you cannot read this one)"
                };
                println!(
                    "  {}  {kind}  {}{note}",
                    channel.channel_id.short(),
                    channel.name
                );
            }
            Ok(())
        }
        ChannelCmd::Invite { channel, peer } => {
            let target = resolve_channel(&store, Some(&channel))?;
            let live = peers_now(&vault, &config, &identity, &store, 3).await?;
            let invitee = mail::resolve_or_explain(&live, &peer)?;

            let sealing = intraweb_core::SealingKey::derive(&identity);
            channels::invite(&store, &identity, &sealing, target, &invitee).await?;

            println!("Invited {} ({}).", invitee.nickname, invitee.fingerprint);
            println!("They can now read everything said in that channel from here on.");
            Ok(())
        }
    }
}

async fn block_command(vault: Vault, query: &str, reason: &str) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    let live = peers_now(&vault, &config, &identity, &store, 3).await?;
    let target = mail::resolve_or_explain(&mail::addressable(&live, &store), query)?;

    {
        let Ok(store) = store.lock() else {
            anyhow::bail!("the keyring is busy");
        };
        store.block(target.peer_id, reason, now_secs())?;
    }

    println!("Blocked {} ({}).", target.nickname, target.fingerprint);
    println!("They are dropped from the roster and their mail is refused.");
    Ok(())
}

async fn unblock_command(vault: Vault, query: &str) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    // A blocked peer is not in the roster, so the keyring is what can name them.
    let candidates = mail::addressable(&[], &store);
    let target = match mail::resolve_or_explain(&candidates, query) {
        Ok(peer) => peer,
        Err(_) => {
            let live = peers_now(&vault, &config, &identity, &store, 2).await?;
            mail::resolve_or_explain(&mail::addressable(&live, &store), query)?
        }
    };

    let Ok(store) = store.lock() else {
        anyhow::bail!("the keyring is busy");
    };
    if store.unblock(target.peer_id)? {
        println!("Unblocked {} ({}).", target.nickname, target.fingerprint);
    } else {
        println!("{} was not blocked.", target.nickname);
    }
    Ok(())
}

fn blocked_command(vault: Vault) -> Result<()> {
    let store = Store::open(&vault.db_path())?;
    let blocked = store.blocked_peers()?;
    if blocked.is_empty() {
        println!("Nobody is blocked.");
        return Ok(());
    }
    for peer_id in blocked {
        println!("  {}  {}", peer_id.fingerprint(), peer_id.to_hex());
    }
    Ok(())
}

async fn ls_command(vault: Vault, query: &str) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    let peers = peers_now(&vault, &config, &identity, &store, 3).await?;
    let peer = mail::resolve_or_explain(&peers, query)?;
    let addr = peer
        .preferred_addr()
        .context("that peer has no address yet")?;

    let response = http::get(addr, peer.api_port, "/api/files", Duration::from_secs(5)).await?;
    anyhow::ensure!(
        response.is_success(),
        "{} answered HTTP {}",
        peer.nickname,
        response.status
    );

    let files: Vec<serde_json::Value> = serde_json::from_str(&response.body)
        .context("that peer sent a file list we could not read")?;
    if files.is_empty() {
        println!("{} is not sharing any files.", peer.nickname);
        return Ok(());
    }

    println!("{} ({})", peer.nickname, peer.fingerprint);
    for file in &files {
        let path = file.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let size = file.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        println!("  {:>10}  {path}", human_size(size));
    }
    println!("\nFetch one with: intraweb get {} <path>", peer.nickname);
    Ok(())
}

async fn get_command(vault: Vault, query: &str, file: &str, output: Option<PathBuf>) -> Result<()> {
    let (identity, config, _) = open_vault(&vault)?;
    let store = Arc::new(Mutex::new(Store::open(&vault.db_path())?));
    let config = Arc::new(config);

    let peers = peers_now(&vault, &config, &identity, &store, 3).await?;
    let peer = mail::resolve_or_explain(&peers, query)?;
    let addr = peer
        .preferred_addr()
        .context("that peer has no address yet")?;

    let destination =
        output.unwrap_or_else(|| PathBuf::from(file.rsplit('/').next().unwrap_or("download")));
    let resuming = tokio::fs::metadata(&destination)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    if resuming > 0 {
        println!("Resuming at {}.", human_size(resuming));
    }

    let path = format!("/files/{file}");
    let mut last_report = 0u64;
    let written = http::stream_to_file(
        addr,
        peer.api_port,
        &path,
        &destination,
        Duration::from_secs(30),
        |written, expected| {
            // Report on the way past each megabyte rather than every chunk.
            if written - last_report < 1024 * 1024 {
                return;
            }
            last_report = written;
            match expected {
                Some(total) if total > 0 => {
                    eprint!("\r  {} / {}  ", human_size(written), human_size(total))
                }
                _ => eprint!("\r  {}  ", human_size(written)),
            }
        },
    )
    .await?;

    eprintln!();
    println!("Saved {} to {}", human_size(written), destination.display());
    Ok(())
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

async fn doctor(vault: Vault, listen: u64) -> Result<()> {
    let (_identity, config, _) = open_vault(&vault)?;

    println!("Listening for {listen}s on both discovery paths...\n");
    let report = intraweb_net::doctor::run(config.beacon_port, Duration::from_secs(listen)).await?;

    for check in &report.checks {
        let mark = match check.status {
            intraweb_net::doctor::Status::Pass => "ok  ",
            intraweb_net::doctor::Status::Warn => "warn",
            intraweb_net::doctor::Status::Fail => "FAIL",
        };
        println!("  [{mark}] {:<18} {}", check.name, check.detail);
        if let Some(remedy) = &check.remedy {
            println!("         {remedy}");
        }
    }

    println!("\n{}", report.verdict);

    // A network that simply has nobody on it is not an error exit.
    if report.worst_status() == intraweb_net::doctor::Status::Fail {
        std::process::exit(1);
    }
    Ok(())
}

fn show_id(vault: Vault) -> Result<()> {
    let (identity, config, minted) = open_vault(&vault)?;
    if minted {
        println!("Minted a new identity.\n");
    }
    println!("nickname     {}", config.sanitized_nickname());
    println!("fingerprint  {}", identity.fingerprint());
    println!("public key   {}", identity.peer_id().to_hex());
    println!("vault        {}", vault.root().display());
    println!("\nRead the fingerprint aloud to a neighbor to verify each other.");
    Ok(())
}

/// Omit the port from URLs when it is the default, so the printed address is
/// the one a person would actually type.
fn suffix(port: u16) -> String {
    if port == 80 {
        String::new()
    } else {
        format!(":{port}")
    }
}

fn init_logging() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_env("INTRAWEB_LOG")
        .unwrap_or_else(|_| EnvFilter::new("intraweb_net=info,intraweb_cli=info,warn"));
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}
