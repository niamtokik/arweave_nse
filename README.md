# Arweave Nmap Script Engine

A way to get more information about Arweave Nodes using nmap. This
script is a work in progress but can already return interesting value.

## Usage

One can try it on mainnet servers hardcoded in arweave source code:

 - `sfo-1.na-west-1.arweave.net`
    ([206.189.70.139](https://api.ipapi.is/?q=206.189.70.139))

 - `ams-1.eu-central-1.arweave.net`
   ([178.62.222.154](https://api.ipapi.is/?q=178.62.222.154))

 - `fra-1.eu-central-2.arweave.net`
   ([157.230.102.219](https://api.ipapi.is/?q=157.230.102.219))

 - `blr-1.ap-central-1.arweave.net`
   ([139.59.19.218](https://api.ipapi.is/?q=139.59.19.218))

 - `sgp-1.ap-central-2.arweave.net`
   ([178.128.89.236](https://api.ipapi.is/?q=178.128.89.236))

### Identify Mode

This mode only return basic information on the target.

```sh
# default scan, using identify mode
nmap -p 1984 --script=arweave.nse 206.189.70.139

# forced scan with identify mode
nmap -p 1984 --script=+arweave.nse 206.189.70.139
```

### Fingerprint Mode

This mode is an advanced identify mode, returning more information and
checking all default end-points.

```sh
# fingerprint mode
nmap -p 1984 --script=arweave.nse --script-args="arweave.mode=fingerprint" 206.189.70.139
```

### (WIP) Fuzzing Mode

This mode create random data for each end-point automatically and
check the result.

```sh
# fuzzing mode
nmap -p 1984 --script=arweave.nse --script-args="arweave.mode=fuzzing" 206.189.70.139
```

### (WIP) Inject mode

This mode is mainly used to inject crafted data.

```sh
# inject mode
nmap -p 1984 --script=arweave.nse --script-args="arweave.mode=inject" 206.189.70.139
```

## TODO

 - [x] HTTP GET method support without parameters
 - [x] HTTP HEAD method
 - [x] HTTP GET method with path parameters
 - [x] HTTP POST method with path parameters and configured body
 - [x] HTTP PUT method with path parameters and configured body
 - [ ] ~~HTTP OPTIONS method~~ (not supported by default nmap library)
 - [ ] Randomized Scanner end-points
 - [ ] Add arguments supports:
   - [ ] `arweave.http_header_content_type="application/json"`
   - [ ] `arweave.randomize=true`: randomize path scan
   - [x] `arweave.mode=identify`: default scan
   - [x] `arweave.mode=fingerprint`:
   - [ ] `arweave.mode=fuzzing`:
   - [ ] `arweave.mode=inject`:
   - [x] `arweave.scan_only=api_id`: scan only one path (bypass scan mode)
   - [x] `arweave.scan_filter=.*`: filter scanned parse (bypass scan mode)
   - [ ] `arweave.http_header_authentication`: add bearer support
 - [x] Custom options for api
   - [x] `arweave.get_price_size.size`
   - [x] `arweave.get_price_size_target.size`
   - [x] `arweave.get_wallet_balance.address`
   - [x] `arweave.get_wallet_last_tx.address`
   - [x] `arweave.get_block_height.height`
   - [x] `arweave.get_block_hash.hash`
   - [x] `arweave.get_tx.tx_id`
   - [x] `arweave.get_tx_offset.tx_id`
   - [x] `arweave.get_tx_state.tx_id`
   - [x] `arweave.get_chunks.offset`
   - [x] `arweave.post_admin_queue_tx.body`
   - [x] `arweave.put_admin_block_data.body`
   - [x] `arweave.get_farcaster_frame_tx.tx_id`
   - [x] `arweave.post_farcaster_frame_tx.tx_id`
   - [x] `arweave.post_block2.body`
   - [x] `arweave.post_block_announcement.body`
   - [x] `arweave.post_block.body`
   - [x] `arweave.post_block.body`
   - [x] `arweave.post_coordinated_mining_h1.body`
   - [x] `arweave.post_coordinated_mining_h2.body`
   - [x] `arweave.post_height.body`
   - [x] `arweave.post_partial_solution.body`
   - [x] `arweave.post_peers.body`
   - [x] `arweave.post_tx.body`
   - [x] `arweave.post_tx2.body`
   - [x] `arweave.post_unsigned_tx.body`
   - [x] `arweave.post_vdf.body`
   - [x] `arweave.post_wallet.body`
 - [ ] Fuzzer:
   - [ ] Simple ETF parser
   - [ ] Simple ETF serializer
   - [ ] Automatic code injection
 - [ ] Other features to add:
   - [ ] CORS headers check
   - [ ] Comments/details regarding a port
   - [ ] custom state for each end-point
   - [ ] Version fingerprinting (e.g. add score in each end-point, seen on each version...)
   - [ ] external service notification support
   - [ ] add risks evaluation on each end-point
   - [ ] includes default bearer/api_secret in the API

# References and resources

[AR.IO Network+Token White
Paper](https://stmnnh3s5hfbfaxxskvhx3d4l5vkbdxnep34ginzy5bsrlzzxxha.arweave.net/lNjWn3LpyhKC95Kqe-x8X2qgju0j98MhucdDKK85vc4)

[AR.IO documentation](https://ar-io.dev/api-docs/)

[AR.IO admin
API](https://docs.ar.io/gateways/ar-io-node/admin/admin-api.html#overview)
