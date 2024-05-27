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

```sh
nmap -p 1984 --script=arweave.nse 206.189.70.139,178.62.222.154,157.230.102.219,139.59.19.218,178.128.89.236
```

Note: like any nmap script, it can also return XML value with `-oX`
flag.

## TODO

 - [x] HTTP GET method support without parameters
 - [x] HTTP HEAD method
 - [x] HTTP GET method with path parameters
 - [ ] HTTP POST method with path parameters and configured body
 - [ ] HTTP OPTIONS method
 - [ ] Randomized Scanner
 - [ ] Add arguments supports:
   - [ ] `arweave.http_header_content_type="application/json"`
   - [ ] `arweave.randomize=true`: randomize path scan
   - [x] `arweave.scan=default`: default scan
   - [x] `arweave.scan=full` (include default): full scan including post and options
   - [ ] `arweave.scan=fuzzer` (include default and full): full scan with totally random value
   - [x] `arweave.scan_only=api_id`: scan only one path (bypass scan mode)
   - [x] `arweave.scan_filter=.*`: filter scanned parse (bypass scan mode)
   - [ ] `arweave.http_header_authentication`: add bearer support
 - [ ] Fuzzer:
   - [ ] Simple ETF parser
   - [ ] Simple ETF serializer
   - [ ] Automatic code injection

# References and resources

[AR.IO Network+Token White
Paper](https://stmnnh3s5hfbfaxxskvhx3d4l5vkbdxnep34ginzy5bsrlzzxxha.arweave.net/lNjWn3LpyhKC95Kqe-x8X2qgju0j98MhucdDKK85vc4)

[AR.IO documentation](https://ar-io.dev/api-docs/)

[AR.IO admin
API](https://docs.ar.io/gateways/ar-io-node/admin/admin-api.html#overview)
