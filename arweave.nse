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
----------------------------------------------------------------------
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
categories = {"default", "discovery", "safe"}
portrule = shortport.port_or_service(1984, "arweave", "tcp", "open")

local api = {
   admin_debug = {
      method = "get",
      path = { "ar-io", "admin", "debug" }
   },
   block_index = {
      method = "get",
      path = { "block_index" }
   },
   block_index2 = {
      method = "get",
      path = { "block_index2" }
   },
   chunk = {
      method = "get",
      path = { "chunk" }
   },
   chunk2 = {
      method = "get",
      path = { "chunk2" }
   },
   chunk_proof = {
      method = "get",
      path = { "chunk_proof" }
   },
   coordinated_mining_partition_table = {
      method = "get",
      path = { "coordinated_mining", "partition_table" }
   },
   coordinated_mining_state = {
      method = "get",
      path = { "coordinated_mining", "state" }
   },
   current_block = {
      method = "get",
      path = { "current_block" }
   },
   data_sync_record = {
      method = "get",
      path = {"data_sync_record" }
   },
   root = {
      method = "get",
      path = {}
   },
   height = {
      method = "get",
      path = { "height" }
   },
   info = {
      method = "get",
      path = { "info" }
   },
   jobs = {
      method = "get",
      path = { "jobs" }
   },
   peers = {
      method = "get",
      path = { "peers" }
   },
   queue = {
      method = "get",
      path = { "queue" }
   },
   rates = {
      method = "get",
      path = { "rates" }
   },
   recent_hash_list_diff = {
      method = "get",
      path = { "recent_hash_list_diff" }
   },
   sync_buckets = {
      method = "get",
      path = { "sync_buckets" }
   },
   time = {
      method = "get",
      path = { "time" }
   },
   total_supply = {
      method = "get",
      path = { "total_supply" }
   },
   tx_anchor = {
      method = "get",
      path = { "tx_anchor" }
   },
   tx_pending = {
      method = "get",
      path = { "tx", "pending" }
   },
   vdf = {
      method = "get",
      path = { "vdf" }
   },
   vdf2 = {
      method = "get",
      path = { "vdf2" }
   },
   vdf2_previous_session = {
      method = "get",
      path = { "vdf2", "previous_session" }
   },
   vdf2_session = {
      method = "get",
      path = { "vdf2", "session" }
   },
   vdf_previous_session = {
      method = "get",
      path = { "vdf", "previous_session" }
   },
   vdf_session = {
      method = "get",
      path = { "vdf", "session" }
   },
   wallet = {
      method = "get",
      path = { "wallet_list" }
   }

   -- price_size = {
   --    path = {"price", { name = "size" } }
   -- },
   -- price_size_target = {
   --    path = { "price", { name = "size" }, "target" }
   -- },
   -- wallet_balance = {
   --    path = { "wallet", { name = "address" }, "balance" }
   -- },
   -- wallet_last_tx = {
   --    path = { "wallet" , { name = "address" }, "last_tx" }
   -- },
   -- block_height = {
   --    path = { "block", "height", { name = "height" } }
   -- },
   -- block_hash = {
   --    path = { "block", "hash", { name = "hash" } }
   -- },
   -- tx = {
   --    path = { "tx", { name = "tx_id" } }
   -- },
   -- tx_offset = {
   --    path = { "tx", { name = "tx_id" }, "offset" }
   -- },
   -- tx_status = {
   --    path = { "tx", { name = "tx_id" } , "status" }
   -- },
   -- chunks = {
   --    path = { "chunk", { name = "offset" } }
   -- }
}

local default_scan = {
   "info", "peers", "time", "rates"
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

   if method ~= "get" then
      error(path_id .. ": unsupported http method (" .. method .. ")")
   end
   response = http.get(host, port, path)

   if (not(response) or response.status ~= 200) then
      return nil
   end

   local status, parsed = json.parse(response.body)

   output.http_path_id = path_id
   output.http_path = path
   output.http_method = method
   output.http_status = response.status
   output.parsed = parsed

   return output
end

-- returns true if it's a gateway or a miner, else false. To do that,
-- this function analyze the JSON object returned by / using get
-- method.
is_gateway = function(host, port)
   local output = http_request(host, port, "root")
   
   if output.http_status ~= 200 then
      return false
   end
   if not(output.parsed.version) then
      return false
   end
   if not(output.parsed.release) then
      return false
   end
   if not(output.parsed.network) then
      return false
   end
   if string.find(output.parsed.network, "^arweave") then
      return true
   end
end

-- entry point
action = function(host, port)
   if is_gateway(host, port) then
      local output = stdnse.output_table()
      local result
      for key, path_id in pairs(default_scan) do
         result = http_request(host, port, path_id)
         output[path_id] = result
      end
      return output
   end
end
