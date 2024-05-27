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

----------------------------------------------------------------------
-- default header used
----------------------------------------------------------------------
local default_headers = {
   {"content-type", "application/json"}
}

----------------------------------------------------------------------
-- api table containing arweave api mapping
----------------------------------------------------------------------
local api = {
   -- no params
   root = {
      scan = "init",
      method = "get",
      path = {}
   },

   -- no params
   get_admin_debug = {
      scan = "default",
      method = "get",
      path = { "ar-io", "admin", "debug" }
   },

   -- no params
   get_block_index = {
      scan = "default",
      method = "get",
      path = { "block_index" }
   },

   -- no params
   get_block_index2 = {
      scan = "default",
      method = "get",
      path = { "block_index2" }
   },

   -- no params
   get_chunk = {
      scan = "default",
      method = "get",
      path = { "chunk" }
   },

   -- no params
   get_chunk2 = {
      scan = "default",
      method = "get",
      path = { "chunk2" }
   },

   -- no params
   get_chunk_proof = {
      scan = "default",
      method = "get",
      path = { "chunk_proof" }
   },

   -- no params
   get_coordinated_mining_partition_table = {
      scan = "full",
      method = "get",
      path = { "coordinated_mining", "partition_table" }
   },

   -- no params
   get_coordinated_mining_state = {
      scan = "full",
      method = "get",
      path = { "coordinated_mining", "state" }
   },

   -- no params
   get_current_block = {
      scan = "full",
      method = "get",
      path = { "current_block" }
   },

   -- no params
   get_data_sync_record = {
      scan = "default",
      method = "get",
      path = { "data_sync_record" }
   },

   -- no params
   get_height = {
      scan = "default",
      method = "get",
      path = { "height" }
   },

   -- no params
   get_info = {
      scan = "default",
      method = "get",
      path = { "info" }
   },

   -- no params
   get_jobs = {
      scan = "default",
      method = "get",
      path = { "jobs" }
   },

   -- no params
   get_peers = {
      scan = "default",
      method = "get",
      path = { "peers" }
   },

   -- no params
   get_queue = {
      scan = "default",
      method = "get",
      path = { "queue" }
   },

   -- no params
   get_rates = {
      scan = "default",
      method = "get",
      path = { "rates" }
   },

   -- no params
   get_recent_hash_list_diff = {
      scan = "default",
      method = "get",
      path = { "recent_hash_list_diff" }
   },

   -- no params
   get_sync_buckets = {
      scan = "default",
      method = "get",
      path = { "sync_buckets" }
   },

   -- no params
   get_time = {
      scan = "default",
      method = "get",
      path = { "time" }
   },

   -- no params
   get_total_supply = {
      scan = "default",
      method = "get",
      path = { "total_supply" }
   },

   -- no params
   get_tx_anchor = {
      scan = "default",
      method = "get",
      path = { "tx_anchor" }
   },

   -- no params
   get_tx_pending = {
      scan = "default",
      method = "get",
      path = { "tx", "pending" }
   },

   -- no params
   get_vdf = {
      scan = "default",
      method = "get",
      path = { "vdf" }
   },

   -- no params
   get_vdf2 = {
      scan = "default",
      method = "get",
      path = { "vdf2" }
   },

   -- no params
   get_vdf2_previous_session = {
      scan = "default",
      method = "get",
      path = { "vdf2", "previous_session" }
   },

   -- no params
   get_vdf2_session = {
      scan = "default",
      method = "get",
      path = { "vdf2", "session" }
   },

   -- no params
   get_vdf_previous_session = {
      scan = "default",
      method = "get",
      path = { "vdf", "previous_session" }
   },

   -- no params
   get_vdf_session = {
      scan = "default",
      method = "get",
      path = { "vdf", "session" }
   },

   -- no params
   get_wallet = {
      scan = "default",
      method = "get",
      path = { "wallet_list" }
   },

   -- no params
   head_root = {
      scan = "full",
      method = "head",
      path = {}
   },

   -- no params
   head_info = {
      scan = "full",
      method = "head",
      path = { "info" }
   },

   -- ok: arweave.get_price_size.size = 123
   get_price_size = {
      scan = "fuzzer",
      method = "get",
      path = { "price", { arg_name = "size" } },
      path_default = {
         size = ""
      }
   },

   -- ok: arweave.get_price_size_target.size = 123
   get_price_size_target = {
      scan = "fuzzer",
      method = "get",
      path = { "price", { arg_name = "size" }, "target" },
      path_default = {
         size = ""
      }
   },

   -- ok: arweave.get_wallet_balance.address = "address"
   get_wallet_balance = {
      scan = "fuzzer",
      method = "get",
      path = { "wallet", { arg_name = "address" }, "balance" },
      path_default = {
         address = ""
      }
   },

   -- ok: arweave.get_wallet_last_tx.address = "address"
   get_wallet_last_tx = {
      scan = "fuzzer",
      method = "get",
      path = { "wallet" , { arg_name = "address" }, "last_tx" },
      path_default = {
         address = ""
      }
   },

   -- ok: arweave.get_block_height.height = 123
   get_block_height = {
      scan = "fuzzer",
      method = "get",
      path = { "block", "height", { arg_name = "height" } },
      path_default = {
         height = 0
      }
   },

   -- ok: arweave.get_block_hash.hash = "hash"
   get_block_hash = {
      scan = "fuzzer",
      method = "get",
      path = { "block", "hash", { arg_name = "hash" } },
      path_default = {
         hash = ""
      }
   },

   -- ok: arweave.get_tx.tx_id = "tx_id"
   get_tx = {
      scan = "fuzzer",
      method = "get",
      path = { "tx", { arg_name = "tx_id" } },
      path_default = {
         tx_id = ""
      }
   },

   -- ok: arweave.get_tx_offset.tx_id = "tx_id"
   get_tx_offset = {
      scan = "fuzzer",
      method = "get",
      path = { "tx", { arg_name = "tx_id" }, "offset" },
      path_default = {
         tx_id = ""
      }
   },

   -- ok: arweave.get_tx_state.tx_id = "tx_id"
   get_tx_status = {
      scan = "fuzzer",
      method = "get",
      path = { "tx", { arg_name = "tx_id" } , "status" },
      path_default = {
         tx_id = ""
      }
   },

   -- ok: arweave.get_chunks.offset = "offset"
   get_chunks = {
      scan = "fuzzer",
      method = "get",
      path = { "chunk", { arg_name = "offset" } },
      path_default = {
         offset = ""
      }
   },

   -- ok: arweave.post_admin_queue_tx.body = ""
   post_admin_queue_tx = {
      scan = "full",
      method = "post",
      path = { "ar-io", "admin", "queue-tx" }
   },

   -- ok: arweave.put_admin_block_data.body = ""
   put_admin_block_data = {
      scan = "full",
      method = "put",
      path = { "ar-io", "admin", "block-data" }
   },

   -- ok: arweave.get_farcaster_frame_tx.tx_id = ""
   get_farcaster_frame_tx = {
      scan = "fuzzer",
      method = "get",
      path = { "local", "farcaster", "frame", { arg_name = "tx_id" } },
      path_default = {
         tx_id = ""
      }
   },

   -- ok: arweave.post_farcaster_frame_tx.tx_id = ""
   -- wip: arweave.post_farcaster_frame_tx.body = ""
   post_farcaster_frame_tx = {
      scan = "fuzzer",
      method = "post",
      path = { "local", "farcaster", "frame", { arg_name = "tx_id" } },
      path_default = {
         tx_id = ""
      }
   },

   -- ok: arweave.post_block2.body = ""
   post_post_block2 = {
      scan = "full",
      method = "post",
      path = { "block2" },
   },

   -- ok: arweave.post_block_announcement.body = ""
   post_block_announcement = {
      scan = "full",
      method = "post",
      path = { "block_announcement" },
   },

   -- ok: arweave.post_block.body = ""
   post_block = {
      scan = "full",
      method = "post",
      path = { "block" },
   },

   -- ok: arweave.post_block.body = ""
   post_chunk = {
      scan = "full",
      method = "post",
      path = { "chunk" },
   },

   -- ok: arweave.post_coordinated_mining_h1.body = ""
   post_coordinated_mining_h1 = {
      scan = "full",
      method = "post",
      path = { "coordinated_mining", "h1" },
   },

   -- ok: arweave.post_coordinated_mining_h2.body = ""
   post_coordinated_mining_h2 = {
      scan = "full",
      method = "post",
      path = { "coordinated_mining", "h2" },
   },

   -- ok: arweave.post_height.body = ""
   post_height = {
      scan = "full",
      method = "post",
      path = { "height" },
   },

   -- ok: arweave.post_partial_solution.body = ""
   post_partial_solution = {
      scan = "full",
      method = "post",
      path = { "partial_solution" }
   },

   -- ok: arweave.post_peers.body = ""
   post_peers = {
      scan = "full",
      method = "post",
      path = { "peers" },
   },

   -- ok: arweave.post_tx.body = ""
   post_tx = {
      scan = "full",
      method = "post",
      path = { "tx" }
   },

   -- ok: arweave.post_tx2.body = ""
   post_tx2 = {
      scan = "full",
      method = "post",
      path = { "tx2" }
   },

   -- ok: arweave.post_unsigned_tx.body = ""
   post_unsigned_tx = {
      scan = "full",
      method = "post",
      path = { "unsigned_tx" }
   },

   -- ok: arweave.post_vdf.body = ""
   -- wip: arweave.post_vdf.fuzzing = true | false
   post_vdf = {
      scan = "full",
      method = "post",
      path = { "vdf" }
   },

   -- ok: arweave.post_wallet.body = ""
   -- wip: arweave.post_wallet.fuzzing = true | false
   post_wallet = {
      scan = "full",
      method = "post",
      path = { "wallet" }
   },

   -- wip: arweave.options_block.fuzzing = true | false
   options_block = {
      scan = "full",
      method = "option",
      path = { "block" }
   },

   -- wip: arweave.options_peers.fuzzing = true | false
   options_peer = {
      scan = "full",
      method = "option",
      path = { "peer" }
   },

   -- wip: arweave.options_tx.fuzzing = true | false
   options_tx = {
      scan = "full",
      method = "tx",
      path = { "tx" }
   }
}

----------------------------------------------------------------------
-- full scan generated with the key present in api data structure
----------------------------------------------------------------------
local full_scan = function()
   local buffer = {}
   for key, value in pairs(api) do
      table.insert(buffer, key)
   end
   return buffer
end

----------------------------------------------------------------------
-- convert a table made of string and table into a path
----------------------------------------------------------------------
http_path = function(path_id)
   local template_path = api[path_id]["path"]
   local path = {}

   for key, value in ipairs(template_path) do

      -- if its a string, we put it in the final path
      if type(value) == "string" then
         table.insert(path, value)
      end

      -- if it's a table, that means this is a variable and we should
      -- fetch the value from arguments by joining the reference
      -- passed previously and the name extracted from the table.
      if type(value) == "table" then
         local name = value["arg_name"]

         -- try to find the default argument used, in the end it could
         -- be a random value generated based on some specification.
         local default_arg = api[path_id]["path_default"][name]

         -- we create nmap argument path
         local arg_path = create_arg_path(path_id, name)

         -- we fetch argument or crash
         local arg = stdnse.get_script_args(arg_path)
            or default_arg
            or error("missing argument: " .. arg_path )

         -- we put the value into the final path
         table.insert(path, arg)
      end
   end

   return "/" .. table.concat(path, "/")
end

----------------------------------------------------------------------
-- create arweave argument path
-- create_arg_path("id", "name") => arweave.id.name
----------------------------------------------------------------------
create_arg_path = function(path_id, name)
   local arg_key = {"arweave", path_id, name}
   return table.concat(arg_key, ".")
end

----------------------------------------------------------------------
-- wrapper around http request for get
----------------------------------------------------------------------
http_request = function(host, port, path_id)
   local output = stdnse.output_table()
   local method = api[path_id]["method"]
   local path = http_path(path_id)
   local response

   -- general information regarding request
   output.http_path_id = path_id
   output.http_path = path
   output.http_method = method

   --------------------------------------------------------------------
   -- get method, assume the content returned is json by default.
   --------------------------------------------------------------------
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

   --------------------------------------------------------------------
   -- head method, returns only headers
   --------------------------------------------------------------------
   if method == "head" then
      response = http.head(host, port, path)

      if not(response) then
         return nil
      end

      -- output headers
      output.http_status = response.status
      output.headers = response.header
      output.body = response.rawbody
      return output
   end

   --------------------------------------------------------------------
   -- post method, disabled for the moment
   --------------------------------------------------------------------
   if method == "post" then
      -- we retrieve the body from arguments. By default, the body is
      -- empty
      local body_arg_path = create_arg_path(path_id, "body")
      local body = stdnse.get_script_args(body_arg_path) or ""
      response = http.post(host, port, path, {}, {}, body)

      if not(response) then
         return nil
      end

      -- if response is not 200 (error?) returns only headers
      if response.status ~= 200 then
         output.http_status = response.status
         output.headers = response.header
         return output
      end

      -- output headers and body
      output.http_status = response.status
      output.headers = response.header
      output.body = response.rawbody
      return output
   end

   error(path_id .. ": unsupported http method (" .. method .. ")")
end

----------------------------------------------------------------------
-- returns true if it's a gateway or a miner, else false. To do that,
-- this function analyze the JSON object returned by / using get
-- method.
----------------------------------------------------------------------
is_gateway = function(host, port)
   local output = http_request(host, port, "root")

   if output.http_status ~= 200 then
      return nil
   end
   if not(output.body.version) then
      return nil
   end
   if not(output.body.release) then
      return nil
   end
   if not(output.body.network) then
      return nil
   end
   if string.find(output.body.network, "^arweave") then
      return output
   end
end

----------------------------------------------------------------------
-- entry point
----------------------------------------------------------------------
action = function(host, port)
   local gateway = is_gateway(host, port)
   if gateway then
      local output = stdnse.output_table()
      local result

      -- set more information about the service
      port.version.name = "arweave"
      port.version.product = gateway.body.network
      port.version.version = gateway.body.version
      port.version.extrainfo = {
         release = gateway.body.release,
         peers = gateway.body.peers,
         height = gateway.body.heigh
      }
      nmap.set_port_version(host, port)

      -- get arweave.scan variable, set to "default" by default
      local scan = stdnse.get_script_args("arweave.scan") or "default"
      local scan_only = stdnse.get_script_args("arweave.scan_only") or nil
      local scan_filter = stdnse.get_script_args("arweave.scan_filter") or nil

      -- scan only one path from api
      if scan_only and api[scan_only] then
         result = http_request(host, port, scan_only)
         output[scan_only] = result
         return output
      end

      -- scan path from api based on regexp
      if scan_filter then
         for key, value in pairs(api) do
            if string.find(key, scan_filter) then
               result = http_request(host, port, key)
               output[key] = result
            end
         end
      end

      -- by default, use scan mode previously set
      for key, value in pairs(api) do
         if value["scan"] == scan then
            result = http_request(host, port, key)
            output[key] = result
         end
      end
      return output

   end
end
