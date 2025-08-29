# RRProxy

RRProxy is a secure proxy tool designed to forward HTTP/HTTPS traffic from a local machine to a remote server through an encrypted tunnel. **The main distinguishing feature of RRProxy is its ability to split large HTTP request bodies into smaller chunks**, which are then transmitted separately to a remote proxy where they are reassembled before being forwarded to the final destination. This chunking mechanism is particularly useful for bypassing network restrictions, size limitations, or deep packet inspection (DPI) systems that may block large requests.

The tool consists of two main components:
- **Local Proxy**: Intercepts client traffic (including TLS), performs chunking and encryption
- **Remote Proxy**: Receives encrypted chunks, reassembles them, and forwards to destination servers

## Architecture and Data Flow

The data flow in RRProxy follows a secure, multi-stage process designed for both security and stealth:

```
┌─────────────┐    HTTP/HTTPS     ┌─────────────────────┐    Encrypted Chunks    ┌──────────────────────┐    Reconstructed     ┌─────────────────┐
│             │  ──────────────►  │                     │  ─────────────────────► │                      │  ──────────────────► │                 │
│   Client    │                   │    Local Proxy      │                         │     Remote Proxy     │                      │   Destination   │
│ (Browser/   │  ◄──────────────  │ • TLS Interception  │  ◄───────────────────── │ • Chunk Assembly     │  ◄────────────────── │     Server      │
│  App)       │   Decrypted       │ • Request Chunking  │    Encrypted Response   │ • Request Forward    │    Original Response │                 │
│             │   Response        │ • ChaCha20 Encrypt  │                         │ • ChaCha20 Decrypt   │                      │                 │
└─────────────┘                   └─────────────────────┘                         └──────────────────────┘                      └─────────────────┘
```

### Detailed Request Flow

1. **Client → Local Proxy**
   - Client sends HTTP/HTTPS request to local proxy
   - For HTTPS: Local proxy performs TLS interception using dynamically generated certificates
   - Local proxy extracts the complete HTTP request (headers + body)

2. **Request Processing & Chunking**
   - If request body size > chunk_size (default: 10KB):
     - Body is split into random-sized chunks (80%-100% of chunk_size)
     - Each chunk is encrypted separately using ChaCha20-Poly1305
     - Metadata headers are added: `X-Request-Id`, `X-Fetch-Id`, `X-Referer`, `X-Robots-Tag`
   - If request body ≤ chunk_size: Sent as single encrypted chunk

3. **Local Proxy → Remote Proxy**
   - Each chunk sent as separate HTTP POST request to remote proxy
   - Original request metadata (method, URL, headers) encrypted and base64-encoded in headers
   - Pre-shared token used for ChaCha20-Poly1305 encryption

4. **Remote Proxy Processing**
   - Receives and decrypts each chunk
   - Assembles chunks using transaction ID and chunk index
   - Once all chunks received, reconstructs original HTTP request
   - Forwards complete request to destination server

5. **Response Path**
   - Destination server responds normally to remote proxy
   - Remote proxy encrypts response and sends back to local proxy
   - Local proxy decrypts and forwards response to client

### Security Features

- **End-to-End Encryption**: All traffic between local and remote proxies encrypted with ChaCha20-Poly1305
- **Dynamic TLS Certificates**: On-the-fly certificate generation for intercepted domains
- **Traffic Obfuscation**: Random chunk sizes and fake headers to reduce fingerprinting
- **Token-Based Authentication**: Pre-shared tokens prevent unauthorized access

## Key Features

### Core Functionality
- **HTTP/HTTPS Proxy**: Supports both plain HTTP and TLS-encrypted HTTPS traffic
- **Request Body Chunking**: Automatically splits large request bodies (>10KB) into smaller, randomly-sized chunks
- **TLS Interception**: Dynamically generates certificates for HTTPS domains using a root CA
- **End-to-End Encryption**: All proxy-to-proxy communication encrypted with ChaCha20-Poly1305

### Advanced Features  
- **Configurable Chunk Size**: Adjust chunk size based on network constraints (default: 10KB)
- **Intermediate Proxy Support**: Can route traffic through additional HTTP proxies
- **Certificate Caching**: Caches generated certificates for performance
- **Request Reassembly**: Intelligent transaction management for chunk reconstruction
- **Stealth Operations**: Uses realistic HTTP headers and user agents to avoid detection

## Installation & Setup

### Prerequisites

- **Rust**: Version 1.70+ with Cargo package manager
- **Operating System**: Windows, Linux, or macOS
- **Network Access**: Ability to run services on chosen ports

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd rrproxy2

# Build release version
just r

# Binary will be available at:
# target/release/rrproxy2      (Linux/macOS)
# target/release/rrproxy2.exe  (Windows)
```

### Cross-Platform Builds

```bash
# For Windows (from Linux/macOS)
cargo xwin build -r --target=x86_64-pc-windows-msvc

# For Linux (from other platforms)  
cargo build -r --target=x86_64-unknown-linux-gnu
```

## Usage Guide

### Quick Start

#### 1. Generate Authentication Token

First, generate a unique token for secure communication:

```bash
./target/release/rrproxy2 remote --generate-token
# Output: 550e8400-e29b-41d4-a716-446655440000
```

#### 2. Set Up Remote Proxy

On your remote server:

```bash
./target/release/rrproxy2 remote \
  --listen 0.0.0.0:9090 \
  --token 550e8400-e29b-41d4-a716-446655440000
```

#### 3. Set Up Local Proxy

On your local machine:

```bash
# Generate CA certificate (first time only)
./target/release/rrproxy2 local --generate-ca

# Start local proxy
./target/release/rrproxy2 local \
  --listen 127.0.0.1:8080 \
  --remote http://YOUR_REMOTE_SERVER:9090 \
  --token 550e8400-e29b-41d4-a716-446655440000
```

#### 4. Configure Client

Configure your browser or application to use `127.0.0.1:8080` as HTTP/HTTPS proxy.

For HTTPS traffic, install the generated `cert.ca.pem` certificate into your system's trusted certificate store.

### Command-Line Options

#### Remote Proxy Options

```bash
rrproxy2 remote [OPTIONS]

OPTIONS:
  -l, --listen <ADDR>     Listen address (default: 127.0.0.1:8080)
  -t, --token <TOKEN>     Encryption token
  -p, --proxy <URL>       Intermediate proxy URL (optional)
  -g, --generate-token    Generate a new UUID token
  -v, --verbose          Increase verbosity (-v debug, -vv trace)
```

#### Local Proxy Options

```bash
rrproxy2 local [OPTIONS]

OPTIONS:
  -l, --listen <ADDR>           Listen address (default: 127.0.0.1:8080)
  -r, --remote <URL>            Remote proxy URL (default: http://127.0.0.1:8081)
  -t, --token <TOKEN>           Encryption token
  -c, --chunk <SIZE>            Chunk size in bytes (default: 10240)
  -p, --proxy <URL>             Intermediate proxy URL (optional)
      --cert <PATH>             CA certificate path (default: cert.ca.pem)
      --key <PATH>              CA private key path (default: key.ca.pem)
      --generate-ca             Generate new CA certificate and key
      --ca-common-name <NAME>   CA common name (default: "RRProxy Root CA")
      --cache-dir <PATH>        Certificate cache directory (default: cert_cache)
  -v, --verbose                Increase verbosity (-v debug, -vv trace)
```

### Configuration Examples

#### Basic Setup

**Remote Server:**
```bash
rrproxy2 remote -l 0.0.0.0:8080 -t my-secret-token
```

**Local Machine:**
```bash
rrproxy2 local -l 127.0.0.1:8080 -r http://remote-server.com:8080 -t my-secret-token
```

#### Custom Chunk Size

For networks with strict size limitations:

```bash
rrproxy2 local -l 127.0.0.1:8080 -r http://remote-server.com:8080 -c 4096 -t my-secret-token
```

#### Using Intermediate Proxy

When routing through another proxy:

```bash
# Remote proxy through corporate proxy
rrproxy2 remote -l 0.0.0.0:8080 -p http://corporate-proxy:3128 -t my-secret-token

# Local proxy through SOCKS proxy  
rrproxy2 local -l 127.0.0.1:8080 -r http://remote-server.com:8080 -p http://socks-proxy:1080 -t my-secret-token
```

#### Custom Certificate Settings

```bash
rrproxy2 local \
  --cert ./my-ca.pem \
  --key ./my-ca-key.pem \
  --cache-dir ./my-cert-cache \
  --ca-common-name "My Custom CA" \
  -r http://remote-server.com:8080 \
  -t my-secret-token
```

## Security Considerations

### Certificate Management

1. **Install Root CA**: Add the generated `cert.ca.pem` to your browser/system trust store
2. **Secure Storage**: Keep the CA private key (`key.ca.pem`) secure and backed up
3. **Certificate Rotation**: Periodically regenerate CA certificates for security

### Token Security

- Use strong, unique tokens for each deployment
- Rotate tokens regularly
- Never share tokens in logs or configuration files
- Use environment variables or secure configuration management

### Network Security

- Run remote proxy on non-standard ports
- Use firewall rules to restrict access to proxy ports
- Consider using VPN or additional encryption layers
- Monitor proxy logs for suspicious activity

## Troubleshooting

### Common Issues

#### Connection Refused
```
Error: Connection refused to remote proxy
```
**Solution**: Check if remote proxy is running and accessible. Verify firewall settings.

#### Certificate Errors
```
Error: Certificate verification failed
```
**Solution**: Ensure CA certificate is properly installed in browser/system trust store.

#### Chunking Problems
```
Error: Failed to reassemble chunks
```
**Solution**: Check network stability and consider reducing chunk size.

#### Authentication Failures
```
Error: Invalid token
```
**Solution**: Verify both local and remote proxies use the same token.

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Debug level
rrproxy2 local -v -l 127.0.0.1:8080 -r http://remote:8080 -t token

# Trace level (very verbose)
rrproxy2 local -vv -l 127.0.0.1:8080 -r http://remote:8080 -t token
```

### Log Files

Logs are automatically saved to:
- `local_proxy_logs/` (local proxy)
- `remote_proxy_logs/` (remote proxy)

## Performance Tuning

### Chunk Size Optimization

- **Small chunks (1-4KB)**: Better for restrictive networks, higher overhead
- **Medium chunks (8-16KB)**: Balanced performance and compatibility  
- **Large chunks (32KB+)**: Better performance, may trigger restrictions

### Network Optimization

- Use local caching for frequently accessed content
- Configure appropriate timeout values
- Monitor bandwidth usage and adjust chunk sizes accordingly
- Consider using multiple proxy instances for load balancing

## Development

### Building for Development

```bash
# Debug build
cargo build

# Run local proxy in development
cargo run -- local -v -l 127.0.0.1:8080

# Run remote proxy in development  
cargo run -- remote -v -l 127.0.0.1:8081
```

### Testing

```bash
# Run unit tests
cargo test

# Run with output
cargo test -- --nocapture

# Test specific module
cargo test crypto::tests
```

### Code Structure

```
src/
├── main.rs           # Application entry point
├── options.rs        # Command-line argument parsing
├── proxy.rs          # Common proxy trait and utilities
├── crypto.rs         # Encryption/decryption (ChaCha20-Poly1305)
├── local.rs          # Local proxy implementation
├── remote.rs         # Remote proxy implementation
├── local/
│   ├── buf.rs        # Buffer management for TLS
│   ├── cert.rs       # Certificate generation and management
│   ├── forward.rs    # Request forwarding and chunking
│   └── tls.rs        # TLS interception handling
└── remote/
    ├── info.rs       # Request metadata parsing
    └── transaction.rs # Chunk assembly and transaction management
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Ensure all tests pass: `cargo test`
5. Submit a pull request

### Code Standards

- Follow Rust standard formatting: `cargo fmt`
- Ensure code passes linting: `cargo clippy`
- Add documentation for public APIs
- Include unit tests for new functionality

## License

This project is licensed under the MIT License.

**MIT License**

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Changelog

### Version 0.1.1 (Current)
- Initial release with basic proxy functionality
- HTTP/HTTPS traffic interception
- Request body chunking mechanism
- ChaCha20-Poly1305 encryption
- Dynamic certificate generation
- Certificate caching system
- Transaction-based chunk reassembly

### Planned Features
- WebSocket proxy support
- HTTP/2 and HTTP/3 compatibility
- Load balancing across multiple remote proxies
- Configuration file support
- Web-based management interface
- Enhanced logging and monitoring
- Docker containerization
