#!/usr/bin/env lua53
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
local stdnse = require "stdnse"
_ENV = stdnse.module("http", stdnse.seeall)

api = {

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
            default = "",
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
            default = "",
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
            default = "",
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
      mode = { "fuzzing", "inject" },
      path = {
         "chunk_proof2",
         {
            arg_name = "offset",
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
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
            default = "1234",
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
            default = "",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "to",
            default = "",
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
            default = "",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "to",
            default = "",
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
            default = "",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "limit",
            default = "",
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
            default = "",
            fuzzer = {
               -- to be defined
            }
         },
         {
            arg_name = "to",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "to",
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "cursor",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "id",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "id",
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "field",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "id",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         "wallet",
         {
            arg_name = "address",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "field",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "network",
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "token",
            default = "",
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
            default = "",
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
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = "",
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
            default = "",
            fuzzer = {}
         },
         {
            arg_name = "address",
            default = "",
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
            default = "",
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
            default = "",
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
   -- options_block = {
   --    mode = "full",
   --    method = "option",
   --    path = { "block" }
   -- },

   -- wip: arweave.options_peers.fuzzing = true | false
   -- options_peer = {
   --    mode = "full",
   --    method = "option",
   --    path = { "peer" }
   -- },

   -- wip: arweave.options_tx.fuzzing = true | false
   -- options_tx = {
   --    mode = "full",
   --    method = "tx",
   --    path = { "tx" }
   -- }
}

