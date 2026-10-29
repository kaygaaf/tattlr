"use strict";

// Just enough tar and zip reading to pull one file out of a GoReleaser
// archive, so the launcher has no dependencies.
const zlib = require("node:zlib");

function fromTarGz(buf, name) {
  const tar = zlib.gunzipSync(buf);
  let off = 0;
  let longName = null;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    let entry = cstr(header.subarray(0, 100));
    const prefix = cstr(header.subarray(345, 500));
    if (prefix) entry = prefix + "/" + entry;
    if (longName !== null) {
      entry = longName;
      longName = null;
    }
    const size = parseInt(cstr(header.subarray(124, 136)).trim() || "0", 8);
    const type = String.fromCharCode(header[156] || 48);
    const body = tar.subarray(off + 512, off + 512 + size);
    if (type === "L") {
      longName = cstr(body);
    } else if ((type === "0" || type === "\0") && base(entry) === name) {
      return Buffer.from(body);
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${name} not found in archive`);
}

function fromZip(buf, name) {
  // End of central directory is in the last 64 KB.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a zip file");
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error("bad zip directory");
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const local = buf.readUInt32LE(off + 42);
    const entry = buf.toString("utf8", off + 46, off + 46 + nameLen);
    if (base(entry) === name) {
      const lname = buf.readUInt16LE(local + 26);
      const lextra = buf.readUInt16LE(local + 28);
      const data = buf.subarray(local + 30 + lname + lextra, local + 30 + lname + lextra + csize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return zlib.inflateRawSync(data);
      throw new Error(`unsupported zip method ${method}`);
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(`${name} not found in archive`);
}

function cstr(b) {
  const i = b.indexOf(0);
  return b.toString("utf8", 0, i < 0 ? b.length : i);
}

function base(p) {
  return p.split("/").pop();
}

module.exports = { fromTarGz, fromZip };
