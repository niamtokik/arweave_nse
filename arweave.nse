----------------------------------------------------------------------
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
-- This Nmap NSE Script was created to identify and fingerprint
-- arweave miners and gateways. Different level of scans are
-- available. This script can also be used as fuzzer or for offensive
-- purpose. It will also include:
--
--   o an ETF (Erlang Term Format) decoder/encoder
--   o a fuzzer using type definition
--   o a notification mechanism to prevent external service
--   o a way to fingerprint the version of the server used
--   o add http pipeline support
--
-- -------------------------------------------------------------------
--
-- @see https://ar-io.dev/api-docs/
-- @see https://docs.ar.io/gateways/ar-io-node/admin/admin-api.html#overview
-- @usage nmap --script=arweave.nse [--script-args=<Args>] <targets>
-- @usage nmap --script=+arweave.nse -p <port> [--script-args=<Args>] <targets>
-- @args arweave.mode (optional): identify (default), fingerprint, fuzzing, inject
-- @args arweave.scan_only (optional): string
-- @args arweave.scan_filter (optional): match pattern string
-- @args arweave.headers (optional)
-- @args arweave.get_balance_address_network_token.address (optional)
-- @args arweave.get_balance_address_network_token.network (optional)
-- @args arweave.get_balance_address_network_token.token (optional)
-- @args arweave.get_block2_type_id.id (optional)
-- @args arweave.get_block2_type_id.type (optional)
-- @args arweave.get_block_hash.hash (optional)
-- @args arweave.get_block_height.height (optional)
-- @args arweave.get_block_height_wallet_address_balance.address (optional)
-- @args arweave.get_block_height_wallet_address_balance.height (optional)
-- @args arweave.get_block_index2_from_to.from (optional)
-- @args arweave.get_block_index2_from_to.to (optional)
-- @args arweave.get_block_index_from_to.from (optional)
-- @args arweave.get_block_index_from_to.to (optional)
-- @args arweave.get_block_time_history_bh.bh (optional)
-- @args arweave.get_block_type_id.id (optional)
-- @args arweave.get_block_type_id.type (optional)
-- @args arweave.get_block_type_id_field.field (optional)
-- @args arweave.get_block_type_id_field.id (optional)
-- @args arweave.get_block_type_id_field.type (optional)
-- @args arweave.get_chunks.offset (optional)
-- @args arweave.get_data_sync_record_start_limit.limit (optional)
-- @args arweave.get_data_sync_record_start_limit.start (optional)
-- @args arweave.get_farcaster_frame_tx.tx_id (optional)
-- @args arweave.get_hash_list2_from_to.from (optional)
-- @args arweave.get_hash_list2_from_to.to (optional)
-- @args arweave.get_hash_list_from_to.from (optional)
-- @args arweave.get_hash_list_from_to.to (optional)
-- @args arweave.get_inflation_height.height (optional)
-- @args arweave.get_is_tx_blacklisted.tx_id (optional)
-- @args arweave.get_jobs_output.prev_output (optional)
-- @args arweave.get_optimistic_price_size.size (optional)
-- @args arweave.get_optimistic_price_size_address.address (optional)
-- @args arweave.get_optimistic_price_size_address.size (optional)
-- @args arweave.get_price2_size.size (optional)
-- @args arweave.get_price2_size_addr.address (optional)
-- @args arweave.get_price2_size_addr.size (optional)
-- @args arweave.get_price_size.size (optional)
-- @args arweave.get_price_size_addr.address (optional)
-- @args arweave.get_price_size_addr.size (optional)
-- @args arweave.get_price_size_target.size (optional)
-- @args arweave.get_reward_history_bh.bh (optional)
-- @args arweave.get_tx.tx_id (optional)
-- @args arweave.get_tx_hash_field.field (optional)
-- @args arweave.get_tx_hash_field.hash (optional)
-- @args arweave.get_tx_offset.tx_id (optional)
-- @args arweave.get_tx_state.tx_id (optional)
-- @args arweave.get_unconfirmed_tx.hash (optional)
-- @args arweave.get_v2price_size_address.address (optional)
-- @args arweave.get_v2price_size_address.size (optional)
-- @args arweave.get_wallet_address_balance.address (optional)
-- @args arweave.get_wallet_address_last_tx.address (optional)
-- @args arweave.get_wallet_address_reserved_rewards_total.address (optional)
-- @args arweave.get_wallet_balance.address (optional)
-- @args arweave.get_wallet_last_tx.address (optional)
-- @args arweave.get_wallet_list_hash.hash (optional)
-- @args arweave.get_wallet_list_hash_address_balance.address (optional)
-- @args arweave.get_wallet_list_hash_address_balance.hash (optional)
-- @args arweave.get_wallet_list_hash_cursor.cursor (optional)
-- @args arweave.get_wallet_list_hash_cursor.hash (optional)
-- @args arweave.post_admin_queue_tx.body (optional)
-- @args arweave.post_block.body (optional)
-- @args arweave.post_block2.body (optional)
-- @args arweave.post_block_announcement.body (optional)
-- @args arweave.post_coordinated_mining_h1.body (optional)
-- @args arweave.post_coordinated_mining_h2.body (optional)
-- @args arweave.post_farcaster_frame_tx.body (optional)
-- @args arweave.post_farcaster_frame_tx.tx_id (optional)
-- @args arweave.post_height.body (optional)
-- @args arweave.post_mine.body (optional)
-- @args arweave.post_partial_solution.body (optional)
-- @args arweave.post_peers.body (optional)
-- @args arweave.post_pool_cm_jobs (optional)
-- @args arweave.post_tx.body (optional)
-- @args arweave.post_tx2.body (optional)
-- @args arweave.post_unsigned_tx.body (optional)
-- @args arweave.post_vdf.body (optional)
-- @args arweave.post_wallet.body (optional)
-- @args arweave.put_admin_block_data.body (optional)
--
-- @output
-- PORT     STATE SERVICE
-- 1984/tcp open  arweave
-- | arweave:
-- |   get_block_index:
-- |     http_path_id: get_block_index
-- |     http_path: /block_index
-- |     http_method: get
-- |     http_status: 400
-- |     headers:
-- |       date: Wed, 29 May 2024 18:15:24 GMT
-- |       server: Cowboy
-- |       content-length: 40
-- |       access-control-allow-origin: *
-- |       connection: close
-- |   get_total_supply:
-- |     http_path_id: get_total_supply
-- |     http_path: /total_supply
-- |     http_method: get
-- |     http_status: 200
-- |     headers:
-- |       date: Wed, 29 May 2024 18:15:26 GMT
-- |       server: Cowboy
-- |       content-length: 20
-- |       access-control-allow-origin: *
-- |       connection: close
-- |_    body: 6.5651199163473e+19
-- Nmap done: 1 IP address (1 host up) scanned in 55.87 seconds
--
-- @TODO add fuzzer support
-- @TODO add application/etf support
-- @TODO randomize api table before scanning
-- @TODO add header support
-- @TODO add default values found in testing
--
----------------------------------------------------------------------
require "strict"
local nmap = require "nmap"
local http = require "http"
local json = require "json"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local rand = require "rand"
local openssl = require "openssl"

----------------------------------------------------------------------
-- default information for nmap engine
----------------------------------------------------------------------
author = "Mathieu Kerjouan"
license = "ISC-OpenBSD"
description = [[
Idendify and collect information about arweave gateways and miners.
]]
categories = {"default", "discovery", "safe", "version"}

----------------------------------------------------------------------
-- extra supported http headers found in arweave source code
----------------------------------------------------------------------
local supported_headers = {
   -- Bearer 123
   -- Bearer 123456
   "authorization",
   "address",
   "anchor",
   "arweave-block-hash",
   "arweave-data-root",
   "arweave-data-size",
   "arweave-recall-byte",
   "arweave-tx-id",
   "content-type",
   "endpoint",
   "modseq",
   "price",
   "signature",
   "timeout",
   "worker",
   "x-bucket-based-offset",
   "x-cm-api-secret",
   "x-internal-api-secret",
   "x-network",
   "x-p2p-port",
   "x-packing",
   "x-pool-api-key",
   "x-release",
}

----------------------------------------------------------------------
-- api table containing arweave api mapping. An end-point is a table
-- containining few mandatories and optional keys:
--   o scan (mandatory): scan mode
--   o method (mandatory): get | post | head
--   o path (mandtory): a table made with string and tables
--   o comment (optional): an optional comment
--   o score (optional): a scoring returned in case of success/failure
--   o version (optional): a way to check the version
--   o body (optional): a way to specify body content
--   o priority (optional):
--   o attack (optional):
--   o notify (optional):
--   o headers (optional): default headers to use
--
-- A path is a table made of string and tables, with mandatories and
-- optional keys:
--  o [string]: static element
--  o [table]: dynamic element
--    o arg_name: the name of this variable
--    o default (optional): the default value if not configured
--    o fuzzer (optional): a function to generate this element
--    o comment (optional):
--    o type (optional):
--    o source (optional): an URL where the value can be found
--
----------------------------------------------------------------------
local api = {

   --------------------------------------------------------------------
   -- no params. used to identify if the node is an active arweave
   -- node
   --------------------------------------------------------------------
   get_root = {
      comment = "default path (/) used to evaluate the server.",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = {}
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_info = {
      comment = "collect node information from /info",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "info" }
   },

   --------------------------------------------------------------------
   -- no params. used to identify if the target is an arweave node.
   --------------------------------------------------------------------
   head_root = {
      comment = "head method used to check if the service is up",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "head",
      path = {}
   },

   --------------------------------------------------------------------
   -- no params. used to identify if the target is an arweave node.
   --------------------------------------------------------------------
   head_info = {
      comment = "head method used to check if the service is up",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "head",
      path = { "info" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_admin_debug = {
      comment = "admin debug interface. It should be close by default.",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "ar-io", "admin", "debug" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_block_index = {
      comment = "get a block, it should return a json object",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "block_index" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_block_index2 = {
      comment = "get a block, it should return etf data",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "block_index2" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk = {
      comment = "get a chunk, it should return a json object",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "chunk" },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk2 = {
      comment = "get a chunk, it should return etf data",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "chunk2" },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk_proof = {
      comment = "",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "chunk_proof" },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk_offset = {
      comment = "",
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "chunk",
         {
            arg_name = "offset",
            default = ":offset",
            fuzzer = {
               t = "number"
            }
         }
      },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk_proof_offset = {
      comment = "",
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "chunk_proof",
         {
            arg_name = "offset",
            default = ":offset",
            fuzzer = {
               t = "number"
            }
         }
      },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk_proof_offset = {
      comment = "",
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "chunk2",
         {
            arg_name = "offset",
            default = ":offset",
            fuzzer = {
               t = "number"
            }
         }
      },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_chunk_proof2_offset = {
      comment = "",
      method = "get",
      mode = { "fuzzing", "inject" },
      path = {
         "chunk_proof2",
         {
            arg_name = "offset",
            default = ":offset",
            fuzzer = {
               t = "number"
            }
         }
      },
      headers = {
         "x-packing",
         "x-bucket-based-offset"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_coordinated_mining_partition_table = {
      comment = "",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "coordinated_mining", "partition_table" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_coordinated_mining_state = {
      comment = "",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "coordinated_mining", "state" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_current_block = {
      comment = "",
      mode = { "fingerprint", "fuzzing", "inject" },
      comment = "deprecated",
      method = "get",
      path = { "current_block" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_data_sync_record = {
      comment = "",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "data_sync_record" },
      headers = {
         "content-type"
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_height = {
      comment = "",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "height" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_jobs = {
      comment = "",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "jobs" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_peers = {
      comment = "",
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "peers" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_queue = {
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      comment = "deprecated end-point",
      method = "get",
      path = { "queue" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_rates = {
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "rates" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_recent_hash_list_diff = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "recent_hash_list_diff" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_sync_buckets = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "sync_buckets" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_time = {
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "time" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_total_supply = {
      mode = { "identify", "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "total_supply" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_tx_anchor = {
      mode = "default",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "tx_anchor" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_tx_pending = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "tx", "pending" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_vdf = {
      mode = "default",
      method = "get",
      path = { "vdf" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_vdf2 = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "vdf2" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_vdf2_previous_session = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "vdf2", "previous_session" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_vdf2_session = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "vdf2", "session" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_vdf_previous_session = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "vdf", "previous_session" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_vdf_session = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "vdf", "session" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_wallet = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "wallet_list" }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_price_size.size = 123
   --------------------------------------------------------------------
   get_price_size = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "price",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {
               t = "number"
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_price_size_target.size = 123
   --------------------------------------------------------------------
   get_price_size_target = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "price",
         {
            arg_name = "size",
            default = "",
            fuzzer = {}
         },
         "target"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_balance.address = "address"
   --------------------------------------------------------------------
   get_wallet_balance = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {
               t = "transaction"
            }
         },
         "balance"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_last_tx.address = "address"
   --------------------------------------------------------------------
   get_wallet_last_tx = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {
               t = "transaction"
            }
         },
         "last_tx"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_height.height = 123
   --------------------------------------------------------------------
   get_block_height = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block",
         "height",
         {
            arg_name = "height",
            default = 2048,
            fuzzer = {
               t = "number",
               size = 32,
               base = 10
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_hash.hash = "hash"
   --------------------------------------------------------------------
   get_block_hash = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block",
         "hash",
         {
            arg_name = "hash",
            default = "WPdv9IsjqGV8MmYv8X-zUPm4MSM-j_Zo9bkUaec1g34",
            fuzzer = {
               t = "number",
               size = 32,
               base = 16
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_tx.tx_id = "tx_id"
   --------------------------------------------------------------------
   get_tx = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "tx",
         {
            arg_name = "tx_id",
            default = ":tx_id",
            fuzzer = {
               t = "transaction"
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_tx_offset.tx_id = "tx_id"
   --------------------------------------------------------------------
   get_tx_offset = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "tx",
         {
            arg_name = "tx_id",
            default = ":tx_id",
            fuzzer = {
               t = "number",
               size = 32,
               base = 64
            }
         },
         "offset"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_tx_state.tx_id = "tx_id"
   --------------------------------------------------------------------
   get_tx_status = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "tx",
         {
            arg_name = "tx_id",
            default = "WPdv9IsjqGV8MmYv8X-zUPm4MSM-j_Zo9bkUaec1g34",
            fuzzer = {
               t = "number",
               size = 32,
               base = 64
            }
         },
         "status"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_chunks.offset = "offset"
   --------------------------------------------------------------------
   get_chunks = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "chunk",
         {
            arg_name = "offset",
            default = ":offset",
            fuzzer = {
               t = "number"
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_admin_queue_tx.body = ""
   --------------------------------------------------------------------
   post_admin_queue_tx = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "ar-io", "admin", "queue-tx" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.put_admin_block_data.body = ""
   --------------------------------------------------------------------
   put_admin_block_data = {
      mode = { "fuzzing", "inject" },
      method = "put",
      path = { "ar-io", "admin", "block-data" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_farcaster_frame_tx.tx_id = ""
   --------------------------------------------------------------------
   get_farcaster_frame_tx = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "local",
         "farcaster",
         "frame",
         {
            arg_name = "tx_id",
            default = "WPdv9IsjqGV8MmYv8X-zUPm4MSM-j_Zo9bkUaec1g34",
            fuzzer = {
               t = "number",
               size = 32,
               base = 64
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_farcaster_frame_tx.tx_id = ""
   -- ok: arweave.post_farcaster_frame_tx.body = ""
   --------------------------------------------------------------------
   post_farcaster_frame_tx = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = {
         "local",
         "farcaster",
         "frame",
         {
            arg_name = "tx_id",
            default = "WPdv9IsjqGV8MmYv8X-zUPm4MSM-j_Zo9bkUaec1g34",
            fuzzer = {
               t = "number",
               size = 32,
               base = 64
            }
         }
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_block2.body = ""
   --------------------------------------------------------------------
   post_post_block2 = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "block2" },
      headers = {
         "arweave-block-hash",
         "arweave-recall-byte"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_block_announcement.body = ""
   --------------------------------------------------------------------
   post_block_announcement = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "block_announcement" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_block.body = ""
   --------------------------------------------------------------------
   post_block = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "block" },
      headers = {
         "arweave-block-hash",
         "arweave-recall-byte"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_block.body = ""
   --------------------------------------------------------------------
   post_chunk = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "chunk" },
      headers = {
         "arweave-data-root",
         "arweave-data-size"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_coordinated_mining_h1.body = ""
   --------------------------------------------------------------------
   post_coordinated_mining_h1 = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "coordinated_mining", "h1" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_coordinated_mining_h2.body = ""
   --------------------------------------------------------------------
   post_coordinated_mining_h2 = {
      mode = "full",
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "coordinated_mining", "h2" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_height.body = ""
   --------------------------------------------------------------------
   post_height = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "height" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_partial_solution.body = ""
   --------------------------------------------------------------------
   post_partial_solution = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "partial_solution" },
      headers = {
         "x-internal-api-secret",
         "x-cm-api-secret"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_peers.body = ""
   --------------------------------------------------------------------
   post_peers = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "peers" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_tx.body = ""
   --------------------------------------------------------------------
   post_tx = {
      mode = { "fuzzing", "inject" },
      comment = "return json encoded transaction",
      method = "post",
      path = { "tx" },
      headers = {
         "arweave-tx-id"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_tx2.body = ""
   --------------------------------------------------------------------
   post_tx2 = {
      mode = { "fuzzing", "inject" },
      comment = "return binary encoded transaction",
      method = "post",
      path = { "tx2" },
      headers = {
         "arweave-tx-id"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_unsigned_tx.body = ""
   --------------------------------------------------------------------
   post_unsigned_tx = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "unsigned_tx" },
      headers = {
         "arweave-tx-id"
      },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_vdf.body = ""
   -- wip: arweave.post_vdf.fuzzing = true | false
   --------------------------------------------------------------------
   post_vdf = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "vdf" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_wallet.body = ""
   -- wip: arweave.post_wallet.fuzzing = true | false
   --------------------------------------------------------------------
   post_wallet = {
      mode = { "fuzzing", "inject" },
      method = "post",
      path = { "wallet" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_index_from_to.from = ""
   -- ok: arweave.get_block_index_from_to.to = ""
   --------------------------------------------------------------------
   get_block_index_from_to = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block_index",
         {
            arg_name = "from",
            default = ":from",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "to",
            default = ":to",
            fuzzer = {
               -- to be defined
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_index2_from_to.from = ""
   -- ok: arweave.get_block_index2_from_to.to = ""
   --------------------------------------------------------------------
   get_block_index2_from_to = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block_index2",
         {
            arg_name = "from",
            default = ":from",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "to",
            default = ":to",
            fuzzer = {
               -- to be defined
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_block_current = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "block", "current" }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_data_sync_record_start_limit.start = ""
   -- ok: arweave.get_data_sync_record_start_limit.limit = ""
   --------------------------------------------------------------------
   get_data_sync_record_start_limit = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "data_sync_record",
         {
            arg_name = "start",
            default = ":start",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "limit",
            default = ":limit",
            fuzzer = {
               -- to be defined
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_recent_hash_list = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "recent_hash_list" }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_hash_list = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "hash_list" }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_hash_list_from_to.from = ""
   -- ok: arweave.get_hash_list_from_to.to = ""
   --------------------------------------------------------------------
   get_hash_list_from_to = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "hash_list",
         {
            arg_name = "from",
            default = ":from",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "to",
            default = ":to",
            fuzzer = {
               -- to be defined
            }
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_hash_list2_from_to.from = ""
   -- ok: arweave.get_hash_list2_from_to.to = ""
   --------------------------------------------------------------------
   get_hash_list2_from_to = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "hash_list2",
         {
            arg_name = "from",
            default = ":from",
            fuzzer = {}
         },
         {
            arg_name = "to",
            default = ":to",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_jobs_output.prev_output = ""
   --------------------------------------------------------------------
   get_jobs_output = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "jobs",
         {
            arg_name = "prev_output",
            default = ":prev_output",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_list_hash.hash = ""
   --------------------------------------------------------------------
   get_wallet_list_hash = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet_list",
         {
            arg_name = "hash",
            default = ":hash",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_list_hash_cursor.hash = ""
   -- ok: arweave.get_wallet_list_hash_cursor.cursor = ""
   --------------------------------------------------------------------
   get_wallet_list_hash_cursor = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet_list",
         {
            arg_name = "hash",
            default = ":hash",
            fuzzer = {}
         },
         {
            arg_name = "cursor",
            default = ":cursor",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_list_hash_address_balance.hash = ""
   -- ok: arweave.get_wallet_list_hash_address_balance.address = ""
   --------------------------------------------------------------------
   get_wallet_list_hash_address_balance = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet_list",
         {
            arg_name = "hash",
            default = ":hash",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         },
         "balance"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_address_balance.address = ""
   --------------------------------------------------------------------
   get_wallet_address_balance = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         },
         "balance"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_address_reserved_rewards_total.address = ""
   --------------------------------------------------------------------
   get_wallet_address_reserved_rewards_total = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         },
         "reserved_rewards_total"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_wallet_address_last_tx.address = ""
   --------------------------------------------------------------------
   get_wallet_address_last_tx = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "wallet",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         },
         "last_tx"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_inflation_height.height = ""
   --------------------------------------------------------------------
   get_inflation_height = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "inflation",
         {
            arg_name = "height",
            default = ":height",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_optimistic_price_size.size = ""
   --------------------------------------------------------------------
   get_optimistic_price_size = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "optimistic_price",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_optimistic_price_size_address.size = ""
   -- ok: arweave.get_optimistic_price_size_address.address = ""
   --------------------------------------------------------------------
   get_optimistic_price_size_address = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "optimistic_price",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_v2price_size_address.size = ""
   -- ok: arweave.get_v2price_size_address.address = ""
   --------------------------------------------------------------------
   get_v2price_size_address = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "v2price",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_reward_history_bh.bh = ""
   --------------------------------------------------------------------
   get_reward_history_bh = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "reward_history",
         {
            arg_name = "bh",
            default = ":bh",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_time_history_bh.bh = ""
   --------------------------------------------------------------------
   get_block_time_history_bh = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block_time_history",
         {
            arg_name = "bh",
            default = ":bh",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_type_id.type = ""
   -- ok: arweave.get_block_type_id.id = ""
   --------------------------------------------------------------------
   get_block_type_id = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block",
         {
            arg_name = "type",
            default = ":type",
            fuzzer = {}
         },
         {
            arg_name = "id",
            default = ":id",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_type_id_field.type = ""
   -- ok: arweave.get_block_type_id_field.id = ""
   -- ok: arweave.get_block_type_id_field.field = ""
   --------------------------------------------------------------------
   get_block_type_id_field = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block",
         {
            arg_name = "type",
            default = ":type",
            fuzzer = {}
         },
         {
            arg_name = "id",
            default = ":id",
            fuzzer = {}
         },
         {
            arg_name = "field",
            default = ":field",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block2_type_id.type = ""
   -- ok: arweave.get_block2_type_id.id = ""
   --------------------------------------------------------------------
   get_block2_type_id = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block2",
         {
            arg_name = "type",
            default = ":type",
            fuzzer = {}
         },
         {
            arg_name = "id",
            default = ":id",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_block_height_wallet_address_balance.height = ""
   -- ok: arweave.get_block_height_wallet_address_balance.address = ""
   --------------------------------------------------------------------
   get_block_height_wallet_address_balance = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "block",
         "height",
         {
            arg_name = "height",
            default = ":height",
            fuzzer = {}
         },
         "wallet",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         },
         "balance"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_tx_hash_field.hash = ""
   -- ok: arweave.get_tx_hash_field.field = ""
   --------------------------------------------------------------------
   get_tx_hash_field = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "tx",
         {
            arg_name = "hash",
            default = ":hash",
            fuzzer = {}
         },
         {
            arg_name = "field",
            default = ":field",
            fuzzer = {}
         }
      },
      header = {
         "content-type"
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_balance_address_network_token.address = ""
   -- ok: arweave.get_balance_address_network_token.network = ""
   -- ok: arweave.get_balance_address_network_token.token = ""
   --------------------------------------------------------------------
   get_balance_address_network_token = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "balance",
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         },
         {
            arg_name = "network",
            default = ":network",
            fuzzer = {}
         },
         {
            arg_name = "token",
            default = ":token",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_is_tx_blacklisted.tx_id = ""
   --------------------------------------------------------------------
   get_is_tx_blacklisted = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "is_tx_blacklisted",
         {
            arg_name = "tx_id",
            default = ":tx_id",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_price2_size.size = ""
   --------------------------------------------------------------------
   get_price2_size = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "price",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_price_size_addr.size = ""
   -- ok: arweave.get_price_size_addr.address = ""
   --------------------------------------------------------------------
   get_price_size_addr = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "price",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = ":address",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_price2_size_addr.size = ""
   -- ok: arweave.get_price2_size_addr.address = ""
   --------------------------------------------------------------------
   get_price2_size_addr = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "price2",
         {
            arg_name = "size",
            default = ":size",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = "address",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- no params
   --------------------------------------------------------------------
   get_tx_ready_for_mining = {
      comment = "only available for testnet miners",
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "get",
      path = { "tx", "ready_for_mining" }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_unconfirmed_tx.hash = ""
   --------------------------------------------------------------------
   get_unconfirmed_tx = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "unconfirmed_tx",
         {
            arg_name = "hash",
            default = ":hash",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.get_unconfirmed_tx.hash = ""
   --------------------------------------------------------------------
   get_unconfirmed_tx = {
      mode = { "fuzzing", "inject" },
      method = "get",
      path = {
         "unconfirmed_tx2",
         {
            arg_name = "hash",
            default = ":hash",
            fuzzer = {}
         }
      }
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_pool_cm_jobs = ""
   --------------------------------------------------------------------
   post_pool_cm_jobs = {
      mode = { "fingerprint", "fuzzing", "inject" },
      method = "post",
      path = { "pool_cm_jobs" },
      body = ""
   },

   --------------------------------------------------------------------
   -- ok: arweave.post_mine.body = ""
   --------------------------------------------------------------------
   post_mine = {
      mode = { "fuzzing", "inject" },
      comment = "only activated for testnet miners",
      method = "post",
      path = { "mine" },
      body = ""
   },

   -- wip: arweave.options_block.fuzzing = true | false
   options_block = {
      mode = {},
      method = "options",
      path = { "block" }
   },

   -- wip: arweave.options_peers.fuzzing = true | false
   options_peer = {
      mode = {},
      method = "options",
      path = { "peer" }
   },

   -- wip: arweave.options_tx.fuzzing = true | false
   options_tx = {
      mode = {},
      method = "options",
      path = { "tx" }
   },
}

----------------------------------------------------------------------
-- dirty way to have rfc4846 base64 using classic base64, just replace
-- the characters... It should work for a big part of values, will do
-- the job for the moment.
--
-- @param s string
-- @return string as base64
----------------------------------------------------------------------
local base64_enc = function(s)
   local base64 = require "base64"
   local output = base64.enc(s)
   output = string.gsub(output, "/", "_")
   output = string.gsub(output, "+", "-")
   output = string.gsub(output, "=", "")
   return output
end

----------------------------------------------------------------------
-- wip: fuzzer function to generate random values and inject them.  it
-- needs to support random number generate, and the output shoud be in
-- hex, base10 or base64.
--
-- @usage fuzzer_number({ t = "number", size = 32, ...})
-- @return random_value
----------------------------------------------------------------------
local fuzzer = function(params)
   if params["t"] == "transaction" then
      return base64_enc(openssl.rand_bytes(32))
   end
   -- if params["t"] == "number" then
   --   return fuzzer_number(params)
   -- end
   error("unsupported fuzzer")
end

----------------------------------------------------------------------
-- wip: this script needs to return different kind of number, in
-- different format and in different bases.
--
-- @usage
-- @return
----------------------------------------------------------------------
local fuzzer_number = function(params)
   -- the size of random data in bytes
   local size = params["size"] or 32

   -- the minimal value allowed
   local min = params["min"] or 0

   -- the maximal value allowed
   local max = params["max"] or 34359738368

   -- the output format, as string, integer, binary...
   local format = params["format"] or "integer"

   -- the base of the number generated
   local base = params["base"] or 10

   -- a rule is a pipeline of functions altering the return of each
   -- values.
   -- local rules = params["rules"] or {}

   -- openssl...

   return nil
end

----------------------------------------------------------------------
-- create arweave argument path
-- create_arg_path("id", "name") => arweave.id.name
--
-- @param path_id a key from api table
-- @param name a string
-- @return string
----------------------------------------------------------------------
local create_arg_path = function(path_id, name)
   local arg_key = {"arweave", path_id, name}
   return table.concat(arg_key, ".")
end

----------------------------------------------------------------------
-- convert a table made of string and table into a path.
--
-- @param path_id the key from api table
-- @return string a formatted end-point
----------------------------------------------------------------------
local http_path = function(path_id)
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
         local default_arg = value["default"]

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
-- wrapper around http request for get.
--
-- @param host nmap host structure
-- @param port nmap port structure
-- @param path_id a key from api table
-- @param options http options
-- @return stdnse.output_table()
----------------------------------------------------------------------
local http_request = function(host, port, path_id, options)
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
      response = http.get(host, port, path, options)

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
      response = http.head(host, port, path, options)

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
      response = http.post(host, port, path, options, {}, body)

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

   --------------------------------------------------------------------
   -- post method, disabled for the moment
   --------------------------------------------------------------------
   if method == "put" then
      -- we retrieve the body from arguments. By default, the body is
      -- empty
      local body_arg_path = create_arg_path(path_id, "body")
      local body = stdnse.get_script_args(body_arg_path) or ""
      response = http.put(host, port, path, options, {}, body)

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
-- returns a value if it's a gateway or a miner, else false. To do
-- that, this function analyze the JSON object returned by / using get
-- method. This is a really simple function but it executes 4
-- requests. Indeed, an arweave node can be identified with head or
-- get request. This is not clean, but this is quite accurate. get /
-- and /info are both working in theory.
--
-- @param host nmap host structure
-- @param port nmap port structure
-- @return output or nil
----------------------------------------------------------------------
local is_gateway = function(host, port, options)
   local get_root  = http_request(host, port, "get_root", options)
   local get_info  = http_request(host, port, "get_info", options)
   local head_root = http_request(host, port, "head_root", options)
   local head_info = http_request(host, port, "head_info", options)

   -- check if they are returning code 200
   if (get_root.http_status  ~= 200) or
      (get_info.http_status  ~= 200) or
      (head_root.http_status ~= 200) or
      (head_info.http_status ~= 200) then
      return nil
   end

   -- check if one of these request return a version;
   if not(get_root.body.version) or
      not(get_info.body.version) then
      return nil
   end

   -- check if the release is present;
   if not(get_root.body.release) or
      not(get_info.body.release) then
      return nil
   end

   -- check if network is present;
   if not(get_root.body.network) or
      not(get_info.body.network) then
      return nil
   end

   -- if network is a string containing arweave, then that's probably
   -- an arweave node.
   if string.find(get_root.body.network, "^arweave") or
      string.find(get_info.body.network, "^arweave") then
      return get_info or get_root
   end

   -- else we assume this server is not an arweave node.
   return nil
end

----------------------------------------------------------------------
-- return the api if mode is defined else return nil.
--
-- @param api_item table
-- @param mode string
-- @return api_item or nil
----------------------------------------------------------------------
local has_mode = function(api_item, mode)

   if not(api_item["mode"]) then
      return nil
   end

   if type(api_item["mode"]) == "string" and api_item["mode"] == mode then
      return api_item
   end

   if type(api_item["mode"]) ~= "table" then
      return nil
   end

   for key, value in ipairs(api_item["mode"]) do
      if value == mode then
         return api_item
      end
   end

   return nil
end

----------------------------------------------------------------------
-- postrule
----------------------------------------------------------------------
portrule = shortport.port_or_service(1984, "arweave", "tcp", "open")

----------------------------------------------------------------------
-- entry point
--
-- @param host nmap host structure
-- @param port nmap port structure
-- @return output or nil
----------------------------------------------------------------------
action = function(host, port)
   -- get arweave.mode variable, set to "identify" by default
   local mode = stdnse.get_script_args("arweave.mode") or "identify"
   local scan_only = stdnse.get_script_args("arweave.scan_only") or nil
   local scan_filter = stdnse.get_script_args("arweave.scan_filter") or nil
   local options = stdnse.get_script_args("arweave.headers") or {}

   -- a dirty way to list available endpoints
   -- scan is dismissed and endpoints are printed
   if mode == "endpoints" then
      local endpoint
      local output = stdnse.output_table()
      local endpoints = {}
      local counter = 0
      for key, value in pairs(api) do
         local method = value["method"]
         local endpoint = http_path(key)
         local curl = { "curl", "-X", method, "http://" .. host.targetname .. ":" .. tostring(port.number) .. endpoint }
         counter = counter+1
         endpoints[key] = {
            method = method,
            endpoint = endpoint,
            curl = table.concat(curl, " ")
         }
      end
      output = {
         nendpoints = counter,
         endpoints = endpoints
      }
      return output
   end

   -- check if the target is a gateway
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

      -- peers mode, only used to return connected peers
      if mode == "peers" then
         stdnse.debug("peers mode enabled: list the peers available on remote server.")
         result = http_request(host, port, "get_peers")
         peers = result.body
         table.sort(peers)
         for i, peer in ipairs(peers) do
            _, _, ipv4, port = string.find(peer, '^(%d+.%d+.%d+.%d+):(%d+)')
            if ipv4 and port then
               output[peer] = {
                  ipv4 = ipv4,
                  port = port
               }
            end
         end
         return output
      end

      -- scan only one path from api
      if scan_only and api[scan_only] then
         stdnse.debug("scan_only enabled: scan only a small subset of endpoints.")
         result = http_request(host, port, scan_only, options)
         output[scan_only] = result
         return output
      end

      -- scan path from api based on regexp
      if scan_filter then
         stdnse.debug("scan_filter enabled: scan only a small subset of endpoints.")
         for key, value in pairs(api) do
            if string.find(key, scan_filter) then
               result = http_request(host, port, key)
               output[key] = result
            end
         end
      end

      -- by default, use scan mode previously set
      for key, value in pairs(api) do
         if has_mode(value, mode) then
            result = http_request(host, port, key)
            output[key] = result
         end
      end

      return output
   end

   return nil
end
