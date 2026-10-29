"use strict";

// Maps Node's platform and arch names to the npm package and the GoReleaser
// archive for that machine.
const GOOS = { darwin: "darwin", linux: "linux", win32: "windows" };
const GOARCH = { x64: "amd64", arm64: "arm64" };

function target(platform = process.platform, arch = process.arch) {
  const goos = GOOS[platform];
  const goarch = GOARCH[arch];
  if (!goos || !goarch) return null;
  const exe = platform === "win32" ? "tattlr.exe" : "tattlr";
  const ext = platform === "win32" ? "zip" : "tar.gz";
  return {
    pkg: `tattlr-${platform}-${arch}`,
    exe,
    archive: (version) => `tattlr_${version}_${goos}_${goarch}.${ext}`,
  };
}

module.exports = { target };
