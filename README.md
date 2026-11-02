<div align="center">
  <img src="https://crystalpng.com/wp-content/uploads/2025/10/Tamasha-Logo.png" alt="Tamasha" width="220" />

# TAMASHA Restream Proxy

High-performance Node.js proxy that authenticates with Tamasha APIs, decrypts eData, resolves signed stream URLs, and restreams HLS output through your own endpoint.

![Node](https://img.shields.io/badge/node-18%2B-1f883d)
![Status](https://img.shields.io/badge/status-active-2ea043)
![Proxy](https://img.shields.io/badge/hls-restream-0969da)
</div>

## Overview

This service:
- Logs in to Tamasha auth APIs and caches tokens.
- Uses refresh-token flow automatically, with login fallback.
- Calls get-channel-url by slug.
- Decrypts eData using AES-256-CBC logic.
- Uses signed m3u8 URLs only in strict order:
  - ChannelStreamingUrls
  - BackupLiveStreamUrl
  - CastStreamingUrls
- Proxies playlists and segments so users stream via your server.

## Endpoints

- GET /health
- GET /:slug/index.m3u8
- GET /:slug/master.m3u8
- GET /proxy?u=<encoded-upstream-url>

Examples:
- /ptv-sports/index.m3u8
- /discovery-channel-live/master.m3u8
