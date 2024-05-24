----------------------------------------------------------------------
--
-- Copyright (c) 2024 Mathieu Kerjouan
--
-- Permission to use, copy, modify, and distribute this software for
-- any purpose with or without fee is hereby granted, provided that
-- the above copyright notice and this permission notice appear in all
-- copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
-- WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
-- AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
-- CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
-- OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
-- NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
-- CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--
-- -------------------------------------------------------------------
--
-- Usage: nmap -p 1984 --script=arweave.nse
-- 
-- -------------------------------------------------------------------
--
-- @output
-- PORT     STATE SERVICE
-- 1984/tcp open  bigbrother
--    | arweave:
--    |   default:
--    |     http_path: /
--    |     http_method: get
--    |     http_status: 200
--    |     parsed:
--    |       queue_length: 0
--    |       network: arweave.N.1
--    |       peers: 507
--    |       height: 1430736
--    |       node_state_latency: 2
--    |       blocks: 538557
--    |       current: R-ezq9VMxr03nF7-IvvLRpp8UfHjMCDBlSTI_c2Yc1o9ZHVNs4bFjQ8eHSuAa8Ke
--    |       version: 5
--    |       release: 69
--    |   info:
--    |     http_path: /info
--    |     http_method: get
--    |     http_status: 200
--    |     parsed:
--    |       queue_length: 0
--    |       network: arweave.N.1
--    |       peers: 507
--    |       height: 1430736
--    |       node_state_latency: 6
--    |       blocks: 538557
--    |       current: R-ezq9VMxr03nF7-IvvLRpp8UfHjMCDBlSTI_c2Yc1o9ZHVNs4bFjQ8eHSuAa8Ke
--    |       version: 5
--    |       release: 69
--    |   peers:
--    |     http_path: /peers
--    |     http_method: get
--    |     http_status: 200
--    |     parsed:
--    |       18.138.235.138:1984
--    |       178.128.89.236:1984
--    |       38.29.227.23:1984
--    |       13.251.3.199:1984
--    |       54.92.124.113:1984
--    |       72.255.241.138:1988
--    |       174.112.132.234:1985
--    |       162.220.53.21:1984
--    |       216.66.68.20:1984
--    |       47.251.16.180:1984
--    |       109.120.235.125:35120
--    |       18.141.221.62:1984
--    |       162.55.176.19:1984
--    |   time:
--    |     http_path: /time
--    |     http_method: get
--    |     http_status: 200
--    |     parsed: 1716549057
--    |   rates:
--    |     http_path: /rates
--    |     http_method: get
--    |     http_status: 200
--    |     parsed:
--    |       payment_methods:
--    |_      endpoints:
--
-- Nmap done: 1 IP address (1 host up) scanned in 2.27 seconds
--
----------------------------------------------------------------------
local http = require "http"
local json = require "json"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

author = "Mathieu Kerjouan"
license = "ISC-OpenBSD"
description = [[
Idendify and collect information about arweave gateways and miners.
]]
categories = {"default", "discovery", "safe"}
portrule = shortport.port_or_service(1984, "arweave", "tcp", "open")

local api = {
   get = {
      block_index = "/block_index",
      block_index2 = "/block_index2",
      chunk = "/chunk",
      chunk2 = "/chunk2",
      chunk_proof = "/chunk_proof",
      coordinated_mining_partition_table = "/coordinated_mining/partition_table",
      coordinated_mining_state = "/coordinated_mining/state",
      current_block = "/current_block",
      data_sync_record = "/data_sync_record",
      default = "/",
      height = "/height",
      info = "/info",
      info = "/info",
      jobs = "/jobs",
      peers = "/peers",
      queue = "/queue",
      rates = "/rates",
      recent_hash_list_diff = "/recent_hash_list_diff",
      sync_buckets = "/sync_buckets",
      time = "/time",
      total_supply = "/total_supply",
      tx_anchor = "/tx_anchor",
      tx_pending = "/tx/pending",
      vdf = "/vdf",
      vdf2 = "/vdf2",
      vdf2_previous_session = "/vdf2/previous_session",
      vdf2_session = "/vdf2/session",
      vdf_previous_session = "/vdf/previous_session",
      vdf_session = "/vdf/session",
      wallet = "wallet_list"
   }
}

local default_scan = {
   "default", "info", "peers", "time", "rates"
}

-- full scan generated with the key present in api data structure
local full_scan = function()
   local buffer = {}
   for key, value in pairs(api["get"]) do
      table.insert(buffer, key)
   end
   return buffer
end

-- wrapper around http request for get
http_get = function(host, port, id)
   local output = stdnse.output_table()   
   local path = api["get"][id]
   local response = http.get(host, port, path)
   if (not(response) or response.status ~= 200) then
      return
   end
   
   local status, parsed = json.parse(response.body)
   
   output.http_path = path
   output.http_method = "get"
   output.http_status = response.status
   output.parsed = parsed

   return output
end

action = function(host, port)
   local output = stdnse.output_table()
   local result
   
   for key, path in pairs(default_scan) do
      result = http_get(host, port, path)
      output[path] = result
   end
   
   return output
end
