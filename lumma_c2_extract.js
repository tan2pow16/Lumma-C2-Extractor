'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/*
 * Copyright (c) 2024-2025, Tangent65536.
 * All rights reserved.
 *
 * License: GNU AGPLv3
 *  (https://www.gnu.org/licenses/agpl-3.0.en.html)
 */

function parse_ascii_cstring_buf(buf, off, lim)
{
  let i = 0;

  off = off ? off : 0;
  lim = lim ? Math.min(buf.length, off + lim) : buf.length;
  for(i = off ; i < lim ; i++)
  {
    if(!buf[i])
    {
      break;
    }

    if(buf[i] < 0x20 || buf[i] >= 0x7F)
    {
      // Not ascii!
      return null;
    }
  }
  return buf.subarray(off, i);
}

function parse_ascii_cstring(buf, off, lim)
{
  return parse_ascii_cstring_buf(buf, off, lim).toString('ascii');
}

function is_buf_base64(buf)
{
  for(let i = 0 ; i < buf.length ; i++)
  {
    if(buf[i] < 0x2F && buf[i] !== 0x2B || buf[i] > 0x39 && buf[i] !== 0x3D && buf[i] < 0x41 || buf[i] > 0x5A && buf[i] < 0x61 || buf[i] > 0x7A)
    {
      return false;
    }
  }
  return true;
}

/*
function get_anchor()
{
  if(!get_anchor.cache)
  {
    let buf = Buffer.allocUnsafe(200);
    for(let i = 0 ; i < 100 ; i++)
    {
      let j = i << 1;
      buf[j] = 0x30 + (i / 10 >> 0);
      buf[j + 1] = 0x30 + (i % 10);
    }
    get_anchor.cache = buf;
  }

  return get_anchor.cache;
}
*/

function get_pe_section(buf, name)
{
  if(buf.length < 0x40 || buf.readUInt16BE(0) !== 0x4D5A)
  {
    return {
      error: 'The input buffer is not a PE file! (MZ header not found)'
    };
  }

  let pe_offset = buf.readUInt32LE(0x3C);
  // 0x120 == sizeof(PE_OPTIONAL_HEADER32) + sizeof(PE_SECTION_HEADER) * 1
  if(buf.length < (pe_offset + 0x120) || buf.readUInt32BE(pe_offset) !== 0x50450000)
  {
    return {
      error: 'The input buffer is not a PE file! (PE magic not found)'
    };
  }

  if(buf.readUInt16LE(pe_offset + 4) !== 0x14C || buf.readUInt16LE(pe_offset + 0x18) !== 0x10B)
  {
    return {
      error: 'The input buffer is not a x86 PE file! Have you unpacked the sample?'
    };
  }

  let image_base = buf.readUInt32LE(pe_offset + 0x34);

  let sections_count = buf.readUInt16LE(pe_offset + 6);
  let section_headers_offset = pe_offset + 0xF8; // For x86 only
  for(let i = 0 ; i < sections_count ; i++)
  {
    let section_header_offset = section_headers_offset + i * 0x28;
    let section_name = parse_ascii_cstring(buf, section_header_offset, 8);

    if(section_name === name)
    {
      let frva = buf.readUInt32LE(section_header_offset + 0x14);
      return {
        image_base: image_base,
        rva: buf.readUInt32LE(section_header_offset + 0xC),
        data: buf.subarray(frva, frva + buf.readUInt32LE(section_header_offset + 0x8))
      };
    }
  }

  return {
    error: 'Unable to locate the `.rdata` section.'
  };
}

function extract_c2(buf)
{
  let rdata = get_pe_section(buf, '.rdata');
  if(rdata.error)
  {
    return rdata;
  }

  let ret = extract_c2_v1(rdata);
  if(ret.results)
  {
    return ret;
  }
  return extract_c2_v2(rdata);
}

function extract_c2_v1(rdata)
{
  // Currently there are always exactly 9 C2 entries.
  const DEFINED_C2_ENTRIES = 9;

  let valid_addr_streak = 0;
  let test_strings = new Array(DEFINED_C2_ENTRIES);
  for(let i = 0 ; i < (rdata.data.length - 3) ; i += 4)
  {
    let test_rrva = rdata.data.readUInt32LE(i) - rdata.image_base - rdata.rva;
    if(test_rrva < 0 || test_rrva >= rdata.data.length)
    {
      valid_addr_streak = 0;
      continue;
    }

    // An artifact of Lumma, that is, a C2 string must not exceed the length of 0x80 bytes (c2str[i][0x80] is the NULL termination)
    if(rdata.data[test_rrva + 0x80] !== 0)
    {
      valid_addr_streak = 0;
      continue;
    }

    let test_buf = parse_ascii_cstring_buf(rdata.data, test_rrva, 0x80);
    if(!test_buf || !is_buf_base64(test_buf))
    {
      valid_addr_streak = 0;
      continue;
    }

    test_strings[valid_addr_streak] = test_buf.toString('ascii');
    valid_addr_streak++;

    const C2_XOR_KEY_LEN = 0x20; // Current observation result
    if(valid_addr_streak == DEFINED_C2_ENTRIES)
    {
      let key = null;
      for(let j = 0 ; j < valid_addr_streak ; j++)
      {
        let cache = Buffer.from(test_strings[j], 'base64');
        if(key)
        {
          // Like memcmp(), non-zero means different.
          if(key.compare(cache.subarray(0, C2_XOR_KEY_LEN)))
          {
            // Assume this streak is invalid, and find the next streak instead.
            valid_addr_streak = 0;
            break;
          }
        }
        else
        {
          key = cache.subarray(0, C2_XOR_KEY_LEN);
        }
        let sub_cache = cache.subarray(C2_XOR_KEY_LEN);
        for(let k = 0 ; k < sub_cache.length ; k++)
        {
          sub_cache[k] ^= key[k % C2_XOR_KEY_LEN];
        }

        // Just reuse the array.
        test_strings[j] = sub_cache.toString('ascii');
      }

      return {
        results: test_strings,
        ver: 1
      };
    }
  }

  return {
    error: 'Unable to locate the (v1) encrypted C2 strings array. Have you unpacked the sample?'
  };
}

function extract_c2_v2(rdata)
{
  // There are also always exactly 9 C2 entries in the latest version.
  const DEFINED_C2_ENTRIES = 9;

  let valid_addr_streak = 0;
  let arr_rrva = -1;
  let valid_rrva_arr = new Uint32Array(DEFINED_C2_ENTRIES);
  for(let i = 0 ; i < (rdata.data.length - 3) ; i += 4)
  {
    let test_rrva = rdata.data.readUInt32LE(i) - rdata.image_base - rdata.rva;
    if(test_rrva < 0 || (test_rrva + 0x80) >= rdata.data.length)
    {
      valid_addr_streak = 0;
      continue;
    }

    // An artifact of Lumma, that is, a C2 string must not exceed the length of 0x80 bytes (c2str[i][0x80] is the NULL termination)
    if(rdata.data[test_rrva + 0x80] !== 0)
    {
      valid_addr_streak = 0;
      continue;
    }

    // If there's more than one test entries, check the gap sizes between them and make sure it's 0x81. Just a compiler artifact that's a nice constant.
    if(valid_addr_streak)
    {
      if(Math.abs(valid_rrva_arr[valid_addr_streak - 1] - test_rrva) % 0x81)
      {
        // Gap is weird, mark it as invalid.
        valid_addr_streak = 0;
        continue;
      }
    }
    else
    {
      arr_rrva = i;
    }

    valid_rrva_arr[valid_addr_streak++] = test_rrva;
    if(valid_addr_streak === DEFINED_C2_ENTRIES)
    {
      // Found the array!
      break;
    }
  }

  if(valid_addr_streak === DEFINED_C2_ENTRIES)
  {
    let ret = new Array(DEFINED_C2_ENTRIES);
    
    let key = rdata.data.subarray(arr_rrva - 40, arr_rrva - 8);
    let iv = Buffer.allocUnsafe(16);
    iv.fill(0, 0, 8);
    rdata.data.copy(iv, 8, arr_rrva - 8, arr_rrva);

    let dcp = crypto.createDecipheriv('chacha20', key, iv);
    for(let i = 0 ; i < DEFINED_C2_ENTRIES ; i++)
    {
      let enc = rdata.data.subarray(valid_rrva_arr[i], valid_rrva_arr[i] + 0x80);
      let dec = dcp.update(enc);
      ret[i] = parse_ascii_cstring(dec);
    }
    dcp.final(); // Should be blank.

    return {
      results: ret,
      ver: 2
    };
  }

  return {
    error: 'Unable to locate the (v2) encrypted C2 strings array. Have you unpacked the sample?'
  };
}

function __main__(args)
{
  if(args.length !== 1)
  {
    console.log('Usage: node %s <path/to/unpacked/lumma.exe>', path.basename(__filename));
    return;
  }

  let buf = null;
  try
  {
    // Yep, I am lazy.
    buf = fs.readFileSync(args[0]);
  }
  catch(err)
  {
    console.error('Error: Unable to open file `%s`.', args[0]);
    console.error(err);
    return;
  }
  let ret = extract_c2(buf);

  if(ret.error)
  {
    console.error('Error: %s', ret.error);
  }
  else
  {
    console.log('Found C2 (v%d):', ret.ver);
    for(let i = 0 ; i < ret.results.length ; i++)
    {
      console.log('[%d] %s', i, ret.results[i]);
    }
  }
}

if(require.main === module)
{
  __main__(process.argv.slice(2));
}
else
{
  module.exports = extract_c2;
}
