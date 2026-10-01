//! Chain data the Electrum server needs but does not index itself.
//!
//! Block hashes come from the oracle, the chain the scanner follows. Headers
//! come from the P2P peer by hash (80 bytes per header via `getheaders`) and
//! are checked against that hash, so the peer cannot substitute another
//! block. The peer's `feefilter` gives its current mempool minimum fee rate.
//!
//! Both connections are reused: the oracle client keeps one gRPC channel,
//! and header requests share one P2P connection that is replaced when it
//! fails or has been idle long enough that the peer may have dropped it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin_rev::Network;
use blindbit_lib::{BlockHeightRequest, OracleServiceClient};
use tokio::sync::Mutex;
use tonic::transport::Channel;

use super::p2p::{P2pError, Peer};
use crate::blockheader;

const ORACLE_TIMEOUT: Duration = Duration::from_secs(15);
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const P2P_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Reuse the header connection only while it is fresh. Bitcoin Core pings
/// every two minutes and this connection only answers when it is used.
const P2P_IDLE_REUSE: Duration = Duration::from_secs(90);
/// A fee filter older than this is refreshed before it is reported.
const FEE_FILTER_MAX_AGE: Duration = Duration::from_secs(10 * 60);

pub struct ChainSource {
    p2p_peer: SocketAddr,
    network: Network,
    oracle_url: String,
    oracle: Mutex<Option<OracleServiceClient<Channel>>>,
    header_peer: Arc<StdMutex<Option<(Peer, Instant)>>>,
    fee_filter: Arc<StdMutex<Option<(u64, Instant)>>>,
}

impl ChainSource {
    pub fn new(p2p_peer: SocketAddr, network: Network, oracle_url: String) -> Self {
        Self {
            p2p_peer,
            network,
            oracle_url,
            oracle: Mutex::new(None),
            header_peer: Arc::new(StdMutex::new(None)),
            fee_filter: Arc::new(StdMutex::new(None)),
        }
    }

    pub fn p2p_peer(&self) -> SocketAddr {
        self.p2p_peer
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The hash of the block the oracle serves at `height`.
    pub async fn block_hash(&self, height: u32) -> Result<BlockHash, String> {
        let mut client = {
            let mut cached = self.oracle.lock().await;
            match cached.as_ref() {
                Some(client) => client.clone(),
                None => {
                    let client = tokio::time::timeout(
                        ORACLE_TIMEOUT,
                        OracleServiceClient::connect(self.oracle_url.clone()),
                    )
                    .await
                    .map_err(|_| "oracle connection timed out".to_string())?
                    .map_err(|error| format!("oracle connection failed: {error}"))?;
                    *cached = Some(client.clone());
                    client
                }
            }
        };
        let request = tonic::Request::new(BlockHeightRequest {
            block_height: u64::from(height),
        });
        let response =
            match tokio::time::timeout(ORACLE_TIMEOUT, client.get_block_hash_by_height(request))
                .await
            {
                Ok(Ok(response)) => response.into_inner(),
                Ok(Err(status)) => {
                    return Err(format!(
                        "oracle hash lookup for height {height} failed: {status}"
                    ));
                }
                Err(_) => {
                    // Start over with a fresh channel next time.
                    *self.oracle.lock().await = None;
                    return Err(format!("oracle hash lookup for height {height} timed out"));
                }
            };
        blockheader::block_hash_from_oracle(response.block_hash).map_err(|error| error.to_string())
    }

    /// The header of block `hash`, from the P2P peer, checked against `hash`.
    pub async fn header(&self, hash: BlockHash) -> Result<Header, String> {
        let header = self
            .with_header_peer(move |peer| {
                peer.headers_by_hash(&[hash], Instant::now() + P2P_REQUEST_TIMEOUT)
            })
            .await?
            .pop()
            .flatten()
            .ok_or_else(|| format!("the P2P peer does not know block {hash}"))?;
        // headers_by_hash already matches by hash; keep the check at this
        // trust boundary so no caller can be handed another block's header.
        if header.block_hash() != hash {
            return Err(format!(
                "P2P peer returned header {} for {hash}",
                header.block_hash()
            ));
        }
        Ok(header)
    }

    /// The peer's current mempool minimum fee rate in sat/kvB.
    pub async fn fee_filter(&self) -> Result<u64, String> {
        if let Some((rate, at)) = *self.fee_filter.lock().expect("fee filter lock")
            && at.elapsed() < FEE_FILTER_MAX_AGE
        {
            return Ok(rate);
        }
        // A fresh connection carries a fresh filter: Bitcoin Core sends it
        // right after the handshake.
        self.header_peer.lock().expect("header peer lock").take();
        self.with_header_peer(|peer| {
            peer.wait_until_settled(Instant::now() + Duration::from_secs(2))?;
            Ok(())
        })
        .await?;
        self.fee_filter
            .lock()
            .expect("fee filter lock")
            .map(|(rate, _)| rate)
            .ok_or_else(|| "the P2P peer did not send a fee filter".to_string())
    }

    /// Remember a fee filter seen on any connection to the peer.
    pub fn note_fee_filter(&self, rate: Option<u64>) {
        note_fee_filter(&self.fee_filter, rate);
    }

    /// Run `request` on the shared header connection, opening it when
    /// needed and retrying once on a fresh connection if it fails.
    async fn with_header_peer<T: Send + 'static>(
        &self,
        request: impl Fn(&mut Peer) -> Result<T, P2pError> + Send + 'static,
    ) -> Result<T, String> {
        let pool = self.header_peer.clone();
        let fee_filter = self.fee_filter.clone();
        let (addr, network) = (self.p2p_peer, self.network);
        tokio::task::spawn_blocking(move || {
            let mut slot = pool.lock().expect("header peer lock");
            let mut last_error = None;
            for _attempt in 0..2 {
                if slot
                    .as_ref()
                    .is_some_and(|(_, used)| used.elapsed() > P2P_IDLE_REUSE)
                {
                    *slot = None;
                }
                if slot.is_none() {
                    match Peer::connect(addr, network, false, P2P_CONNECT_TIMEOUT) {
                        Ok(peer) => *slot = Some((peer, Instant::now())),
                        Err(error) => {
                            last_error = Some(error);
                            continue;
                        }
                    }
                }
                let (peer, used) = slot.as_mut().expect("connected above");
                match request(peer) {
                    Ok(value) => {
                        *used = Instant::now();
                        note_fee_filter(&fee_filter, peer.fee_filter());
                        return Ok(value);
                    }
                    Err(error) => {
                        *slot = None;
                        last_error = Some(error);
                    }
                }
            }
            Err(last_error.map_or_else(|| "P2P request failed".to_string(), |e| e.to_string()))
        })
        .await
        .map_err(|error| format!("P2P task failed: {error}"))?
    }
}

fn note_fee_filter(slot: &StdMutex<Option<(u64, Instant)>>, rate: Option<u64>) {
    if let Some(rate) = rate {
        *slot.lock().expect("fee filter lock") = Some((rate, Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::electrum::fake_peer::{self, FakePeer, Script};
    use bitcoin::hashes::Hash;

    fn to_header(wire: &bitcoin_rev::block::Header) -> Header {
        bitcoin::consensus::encode::deserialize(&bitcoin_rev::consensus::encode::serialize(wire))
            .unwrap()
    }

    #[tokio::test]
    async fn headers_come_by_hash_and_are_checked() {
        let known = fake_peer::header(1);
        let script = Script {
            headers: vec![known],
            fee_filter: 100,
            ..Script::default()
        };
        let peer = FakePeer::spawn(script, 1);
        let chain = ChainSource::new(peer.addr, Network::Regtest, "http://127.0.0.1:1".into());

        let expected = to_header(&known);
        assert_eq!(chain.header(expected.block_hash()).await.unwrap(), expected);
        let unknown = chain.header(BlockHash::all_zeros()).await.unwrap_err();
        assert!(unknown.contains("does not know block"), "{unknown}");
        // One connection served both requests and carried the fee filter.
        assert_eq!(chain.fee_filter().await.unwrap(), 100);
        assert_eq!(
            peer.commands()
                .iter()
                .filter(|c| *c == "getheaders")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn an_unreachable_oracle_is_an_error() {
        let chain = ChainSource::new(
            "127.0.0.1:1".parse().unwrap(),
            Network::Regtest,
            "http://127.0.0.1:1".into(),
        );
        assert!(chain.block_hash(5).await.is_err());
    }
}
