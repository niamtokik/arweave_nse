#!/usr/bin/env lua53
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
-- This script is a quick and dirty implementation of ETF (erlang term
-- format) in lua. The goal is to offer an high level encoder/decoder
-- in lua with enough flexibility to inject randomized data. The idea
-- is to use a table with at least two keys, "t" and "value". "t"
-- contains the type as string, and "value" contains the value as
-- string, number or table
--
-- atom: { t = "atom", value = "test" }
-- small_atom_utf8_ext: { t = "small_atom_utf8_ext", value = "test" }
-- small_atom_ext: { t = "small_atom_ext", value = "test" }
-- atom_ext: { t = "atom_ext", value = "test" }
-- atom_utf8_ext: { t = "atom_utf8_ext", value = "test" }
--
-- empty list: { t = "list", value = {} }
-- list: {
--   t = "list", value = {
--     { t = "atom", value = "test" },
--     { t = "atom", value = "test2" }
--   }
-- }
--
-- binary: {
--   t = "binary", value = {1, 2, 3, 4}
-- }
--
-- map: {
--   t = "map", value = {
--     { t = "atom", value = "test" }, { t = "atom", value = "test" },
--     { t = "atom", value = "test2" }, { t = "atom", value = "test2" },
--   }
-- }
--
----------------------------------------------------------------------

local etf_encode_small_atom_utf8_ext = function(value, state)
   if type(value) == "string" and #value<256 then
      table.insert(state, 119)
      table.insert(state, #value)
      for i=1, #value do
         table.insert(state, string.byte(value, i))
      end
      return state
   end
   error("invalid small_atom_utf8_ext")
end

local etf_encode_atom_utf8_ext = function(value, state)
   if type(value) == "string" and #value>=256 and #value<65536 then
      table.insert(state, 118)
      local left = (#value & 0x00ff)
      local right = (#value & 0xff00) >> 8
      table.insert(state, left)
      table.insert(state, right)
      for i=1, #value do
         table.insert(state, string.byte(value, i))
      end
      return state
   end
   error("invalid atom_utf8_ext")
end

local etf_encode_small_atom_ext = function(value, state)
   if type(value) == "string" and #value<256 then
      table.insert(state, 115)
      table.insert(state, #value)
      for i=1, #value do
         table.insert(state, string.byte(value, i))
      end
      return state
   end
   error("invalid small_atom_ext")
end

local etf_encode_atom_ext = function(value, state)
   if type(value) == "string" and #value>=256 and #value<65536 then
      table.insert(state, 100)
      local left = (#value & 0x00ff)
      local right = (#value & 0xff00) >> 8
      table.insert(state, left)
      table.insert(state, right)
      for i=1, #value do
         table.insert(state, string.byte(value, i))
      end
      return state
   end
   error("invalid atom_ext")
end

local p = function(t)
   local buffer = ""
   for _, v in ipairs(t) do
      buffer = buffer .. string.char(v)
   end
   print(buffer)
end

local etf_encode = function(list)
   local buffer = { 131 }

   -- if the list is containing keys t and value then that probably a
   -- term
   if list["t"] == "small_atom_ext" and list["value"] then
      local value = v["value"]
      local atom = etf_encode_small_atom_ext(value, buffer)
      p(atom)
   end

   if list["t"] == "small_atom_utf8_ext" and list["value"] then
      local value = v["value"]
      local atom = etf_encode_small_atom_utf8_ext(value, buffer)
      p(atom)
   end
end

etf_encode({{ t = "small_atom_ext", value = "test" }})
