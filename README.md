# V2Ray Config Checker

A production-ready Python tool for automatically validating V2Ray proxy configurations. Features a two-phase validation pipeline for maximum efficiency and accuracy.

## Features

- **Dual-Phase Validation**: TCP precheck (fast filtering) + Xray validation (accurate testing)
- **Remote Config Sources**: Automatically fetches configs from 3 curated sources
- **Deduplication**: Removes duplicate configurations intelligently
- **Parallel Processing**: Tests multiple configs simultaneously for speed
- **GitHub Actions Ready**: Fully automated checks every 20 minutes with auto-commit
- **Protocol Support**: VLESS, VMess, Shadowsocks, Trojan
- **Zero Dependencies**: Uses only Python standard library

## Architecture

### Phase 1: TCP Precheck
- Fast network connectivity test
- Validates DNS resolution
- Tests TCP connection to proxy server
- Basic SSL/TLS handshake for secure protocols
- Filters out ~50%+ dead configs before Xray phase
- Typical speed: 500-1000 configs/minute

### Phase 2: Xray Validation
- Full proxy connection test through Xray
- Measures actual latency
- Only tests configs that passed TCP precheck
- Typical speed: 30-50 configs/minute

## Configuration Sources

The checker automatically fetches configs from:

1. `MatinGhanbari/v2ray-configs`
2. `barry-far/V2ray-Config`
3. `ebrasha/free-v2ray-public-list`

All sources are deduplicated before testing.

## Installation

### Local Usage

1. Clone the repository:
```bash
git clone https://github.com/yourusername/v2ray-config-checker
cd v2ray-config-checker
```

2. Install Xray:
   - **Windows**: Download from [Xray-core releases](https://github.com/XTLS/Xray-core/releases)
   - **Linux**: `wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && unzip && sudo mv xray /usr/local/bin/`
   - **macOS**: `brew install xray`

3. Run the checker:
```bash
python v2ray_checker.py
```

Results are saved to `result.txt`.

### GitHub Actions

This repository includes a GitHub Actions workflow that:
- Runs every 20 minutes
- Automatically tests all configs
- Commits and pushes updated results
- Avoids infinite loops by checking for actual changes

To enable:
1. Fork this repository
2. Ensure GitHub Actions is enabled
3. Workflow runs automatically on schedule

## Usage

### Basic Run
```bash
python v2ray_checker.py
```

### Output Format
Results are saved to `result.txt` with format:
```
# V2Ray Config Checker Results
# Generated: 2024-01-15 10:30:45
# Working configs: 42
# ==================================================

# [VLESS] Latency: 125ms | Config Name
vless://uuid@server:port?params#name

# [VMESS] Latency: 145ms | Another Config
vmess://base64encodedconfig
```

Configs are sorted by latency (fastest first).

## Project Structure

```
.
├── v2ray_checker.py          Main entry point
├── src/
│   ├── __init__.py
│   ├── parser.py             Config URL parsing
│   ├── tcp_checker.py        Phase 1: TCP validation
│   ├── xray_validator.py     Phase 2: Xray validation
│   └── config_sources.py     Remote source fetching & dedup
├── .github/
│   └── workflows/
│       └── check.yml         GitHub Actions workflow
├── result.txt                Output file (generated)
├── requirements.txt          Dependencies (none)
├── .gitignore
└── README.md
```

## Development

### Code Structure

- **Clean, production-ready code** with minimal comments
- **Type hints** for better IDE support
- **Modular design** - each component has single responsibility
- **Thread-safe** concurrent processing
- **Graceful error handling** - continues on individual config failures

### Protocol Parsers

The `ConfigParser` class supports:
- **VLESS**: `vless://uuid@host:port?params#name`
- **VMess**: `vmess://base64json`
- **Shadowsocks**: `ss://method:password@host:port#name`
- **Trojan**: `trojan://password@host:port?params#name`

## Performance

Typical performance with modern hardware:

| Phase | Speed | Config Count |
|-------|-------|--------------|
| Fetch & Parse | ~1000 configs/sec | N/A |
| TCP Precheck | 500-1000 configs/min | All |
| Xray Validation | 30-50 configs/min | TCP-passed only |

Example: 1000 configs → 500 pass TCP (5 min) → 50 pass Xray (17 min) = ~22 min total

## Troubleshooting

### Xray Not Found
- Ensure Xray executable is in PATH
- On Windows, place `xray.exe` in the project directory
- On Linux/macOS, install via package manager or place in `/usr/local/bin/`

### No Configs Fetched
- Check internet connectivity
- Verify source URLs are accessible
- Sources may be temporarily unavailable - checker retries automatically

### Low Pass Rate
- Source configs may be outdated
- Network blocking may affect certain protocols
- Consider running from different location/network

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Please ensure:
- Code follows existing style
- No external dependencies added
- Tests pass for any changes
- Commit messages are clear

## Resources

- [Xray-core Documentation](https://xtls.github.io/)
- [VLESS Protocol](https://github.com/XTLS/VLESS)
- [VMess Protocol](https://www.v2fly.org/)
- [Trojan Protocol](https://trojan-gfw.github.io/)
- [Shadowsocks](https://shadowsocks.org/)

## Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Provide config samples (sanitized) if reporting parsing bugs
