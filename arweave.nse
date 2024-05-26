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
-- https://ar-io.dev/api-docs/
-- https://docs.ar.io/gateways/ar-io-node/admin/admin-api.html#overview
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
-- @TODO add HTTP POST method support
-- @TODO add HTTP OPTIONS method support
-- @TODO add script argument support
-- @TODO add fuzzer
-- @TODO add application/etf support
-- @TODO randomize api table before scanning
--
----------------------------------------------------------------------
local nmap = require "nmap"
local http = require "http"
local json = require "json"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local rand = require "rand"

author = "Mathieu Kerjouan"
license = "ISC-OpenBSD"
description = [[
Idendify and collect information about arweave gateways and miners.
]]
categories = {"default", "discovery", "safe", "version"}
portrule = shortport.port_or_service(1984, "arweave", "tcp", "open")

local default_headers = {
   {"content-type", "application/json"}
}

local api = {
   -- get methods without parameters
   admin_debug = {
      scan = "default",
      method = "get",
      path = { "ar-io", "admin", "debug" }
   },
   block_index = {
      scan = "default",
      method = "get",
      path = { "block_index" }
   },
   block_index2 = {
      scan = "default",
      method = "get",
      path = { "block_index2" }
   },
   chunk = {
      scan = "default",
      method = "get",
      path = { "chunk" }
   },
   chunk2 = {
      scan = "default",
      method = "get",
      path = { "chunk2" }
   },
   chunk_proof = {
      scan = "default",
      method = "get",
      path = { "chunk_proof" }
   },
   coordinated_mining_partition_table = {
      scan = "full",
      method = "get",
      path = { "coordinated_mining", "partition_table" }
   },
   coordinated_mining_state = {
      scan = "full",
      method = "get",
      path = { "coordinated_mining", "state" }
   },
   current_block = {
      scan = "full",
      method = "get",
      path = { "current_block" }
   },
   data_sync_record = {
      scan = "default",
      method = "get",
      path = { "data_sync_record" }
   },
   root = {
      scan = "init",
      method = "get",
      path = {}
   },
   height = {
      scan = "default",
      method = "get",
      path = { "height" }
   },
   info = {
      scan = "default",
      method = "get",
      path = { "info" }
   },
   jobs = {
      scan = "default",
      method = "get",
      path = { "jobs" }
   },
   peers = {
      scan = "default",
      method = "get",
      path = { "peers" }
   },
   queue = {
      scan = "default",
      method = "get",
      path = { "queue" }
   },
   rates = {
      scan = "default",
      method = "get",
      path = { "rates" }
   },
   recent_hash_list_diff = {
      scan = "default",
      method = "get",
      path = { "recent_hash_list_diff" }
   },
   sync_buckets = {
      scan = "default",
      method = "get",
      path = { "sync_buckets" }
   },
   time = {
      scan = "default",
      method = "get",
      path = { "time" }
   },
   total_supply = {
      scan = "default",
      method = "get",
      path = { "total_supply" }
   },
   tx_anchor = {
      scan = "default",
      method = "get",
      path = { "tx_anchor" }
   },
   tx_pending = {
      scan = "default",
      method = "get",
      path = { "tx", "pending" }
   },
   vdf = {
      scan = "default",
      method = "get",
      path = { "vdf" }
   },
   vdf2 = {
      scan = "default",
      method = "get",
      path = { "vdf2" }
   },
   vdf2_previous_session = {
      scan = "default",
      method = "get",
      path = { "vdf2", "previous_session" }
   },
   vdf2_session = {
      scan = "default",
      method = "get",
      path = { "vdf2", "session" }
   },
   vdf_previous_session = {
      scan = "default",
      method = "get",
      path = { "vdf", "previous_session" }
   },
   vdf_session = {
      scan = "default",
      method = "get",
      path = { "vdf", "session" }
   },
   wallet = {
      scan = "default",
      method = "get",
      path = { "wallet_list" }
   },

   -- head methods
   head_root = {
      scan = "full",
      method = "head",
      path = {}
   },
   head_info = {
      scan = "full",
      method = "head",
      path = { "info" }
   },

   -- get methods with arguments in path
   price_size = {
      scan = "full",
      method = "get",
      path = {"price", { name = "size" } }
   },
   price_size_target = {
      scan = "full",
      method = "get",
      path = { "price", { name = "size" }, "target" }
   },
   wallet_balance = {
      scan = "full",
      method = "get",
      path = { "wallet", { name = "address" }, "balance" }
   },
   wallet_last_tx = {
      scan = "full",
      method = "get",
      path = { "wallet" , { name = "address" }, "last_tx" }
   },
   block_height = {
      scan = "full",
      method = "get",
      path = { "block", "height", { name = "height" } }
   },
   block_hash = {
      scan = "full",
      method = "get",
      path = { "block", "hash", { name = "hash" } }
   },
   tx = {
      scan = "full",
      method = "get",
      path = { "tx", { name = "tx_id" } }
   },
   tx_offset = {
      scan = "full",
      method = "get",
      path = { "tx", { name = "tx_id" }, "offset" }
   },
   tx_status = {
      scan = "full",
      method = "get",
      path = { "tx", { name = "tx_id" } , "status" }
   },
   chunks = {
      scan = "full",
      method = "get",
      path = { "chunk", { name = "offset" } }
   },
   admin_queue_tx = {
      scan = "full",
      method = "post",
      path = { "ar-io", "admin", "queue-tx" }
   },
   admin_block_data = {
      scan = "full",
      method = "put",
      path = { "ar-io", "admin", "block-data" }
   },
   get_farcaster_frame_tx = {
      scan = "full",
      method = "get",
      path = { "local", "farcaster", "frame", { name = "tx_id" } }
   },

   -- post methods with body and/or parameters in path
   post_farcaster_frame_tx = {
      scan = "fuzzer",
      method = "post",
      path = { "local", "farcaster", "frame", { name = "tx_id" } },
      params = {}
   },
   post_block2 = {
      scan = "fuzzer",
      method = "post",
      path = { "block2" },
      params = {}
   },
   post_block_announcement = {
      scan = "fuzzer",
      method = "post",
      path = { "block_announcement" },
      params = {}
   },
   post_block = {
      scan = "fuzzer",
      method = "post",
      path = { "block" },
      params = {}
   },
   post_chunk = {
      scan = "fuzzer",
      method = "post",
      path = { "chunk" },
      params = {}
   },
   post_coordinated_mining_h1 = {
      scan = "fuzzer",
      method = "post",
      path = { "coordinated_mining", "h1" },
      params = {}
   },
   post_coordinated_mining_h2 = {
      scan = "fuzzer",
      method = "post",
      path = { "coordinated_mining", "h2" },
      params = {}
   },
   post_height = {
      scan = "fuzzer",
      method = "post",
      path = { "height" },
      params = {}
   },
   post_partial_solution = {
      scan = "fuzzer",
      method = "post",
      path = { "partial_solution" },
      params = {}
   },
   post_peers = {
      scan = "fuzzer",
      method = "post",
      path = { "peers" },
      params = {}
   },
   post_tx = {
      scan = "fuzzer",
      method = "post",
      path = { "tx" },
      params = {}
   },
   post_tx2 = {
      scan = "fuzzer",
      method = "post",
      path = { "tx2" },
      params = {}
   },
   post_unsigned_tx = {
      scan = "fuzzer",
      method = "post",
      path = { "unsigned_tx" },
      params = {}
   },
   post_vdf = {
      scan = "fuzzer",
      method = "post",
      path = { "vdf" },
      headers = default_headers,
      params = {}
   },
   post_wallet = {
      scan = "fuzzer",
      method = "post",
      path = { "wallet" },
      headers = default_headers,
      params = {}
   },

   -- options method
   options_block = {
      scan = "full",
      method = "option",
      path = { "block" }
   },
   options_peer = {
      scan = "full",
      method = "option",
      path = { "peer" }
   },
   options_tx = {
      scan = "full",
      method = "tx",
      path = { "tx" }
   }
}

-- full scan generated with the key present in api data structure
local full_scan = function()
   local buffer = {}
   for key, value in pairs(api) do
      table.insert(buffer, key)
   end
   return buffer
end

-- convert a table made of string and table into a path
http_path = function(list, params)
   local path = {}
   for key, value in ipairs(list) do
      if type(value) == "string" then
         table.insert(path, value)
      end
      if type(value) == "table" then
         local name = value["name"]
         local param = params[name]
         table.insert(path, param)
      end
   end
   return "/" .. table.concat(path, "/")
end

-- wrapper around http request for get
http_request = function(host, port, path_id, params)
   local output = stdnse.output_table()
   local method = api[path_id]["method"]
   local path = http_path(api[path_id]["path"])
   local response

   -- general information regarding request
   output.http_path_id = path_id
   output.http_path = path
   output.http_method = method

   -- get method, assume the content returned is json by default.
   if method == "get" then
      response = http.get(host, port, path)

      -- if no response returns nil
      if not(response) then
         return nil
      end

      -- if response is not 200 (error?) returns only headers
      if response.status ~= 200 then
         output.http_status = response.status
         output.headers = response.header
         return output
      end

      -- output headers
      output.http_status = response.status
      output.headers = response.header

      -- we assume the response is correct and returned http/200, then
      -- body is probably a json.
      local status, parsed = json.parse(response.body)
      if status then
         output.body = parsed
      else
         output.body = response.rawbody
      end

      return output
   end

   -- head method, returns only headers
   if method == "head" then
      response = http.head(host, port, path)

      if not(response) then
         return nil
      end

      -- output headers
      output.headers = response.header
      return output
   end

   if method ~= "get" or method ~= "head" then
      error(path_id .. ": unsupported http method (" .. method .. ")")
   end
end

-- returns true if it's a gateway or a miner, else false. To do that,
-- this function analyze the JSON object returned by / using get
-- method.
is_gateway = function(host, port)
   local output = http_request(host, port, "root")

   if output.http_status ~= 200 then
      return false
   end
   if not(output.body.version) then
      return false
   end
   if not(output.body.release) then
      return false
   end
   if not(output.body.network) then
      return false
   end
   if string.find(output.body.network, "^arweave") then
      return output
   end
end

-- entry point
action = function(host, port)
   if is_gateway(host, port) then
      local output = stdnse.output_table()
      local result

      -- get arweave.scan variable, set to "default" by default
      local scan = stdnse.get_script_args("arweave.scan") or "default"

      -- set more information about the service
      port.version.name = "arweave"
      port.version.product = output.network
      port.version.version = output.version
      port.version.extrainfo = {
         release = output.release,
         peers = output.peers,
         height = output.heigh
      }
      nmap.set_port_version(host, port)

      for key, value in pairs(api) do
         if value["scan"] == scan then
            result = http_request(host, port, key)
            output[key] = result
         end
      end

      return output
   end
end
