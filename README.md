# Mass JARM

A high-performance, threaded implementation of [JARM](https://github.com/salesforce/jarm) fingerprinting with smart port detection, rate limiting, and flexible input/output options.

## 🚀 Features

- **Multi-threaded scanning** with configurable thread pools
- **Smart port detection** - automatically scans common SSL/TLS ports
- **Rate limiting** to control scan speed and avoid overwhelming targets
- **Flexible input** - single target, file input, mixed IPs/domains
- **CSV export** with detailed results including timestamps
- **Progress tracking** with real-time update

## 📋 Requirements

- Python 3.6+
- No external dependencies (uses only Python standard library)

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/op7ic/massJARM/
cd massJARM

# Make the script executable
chmod +x massJARM.py

# Run directly
python3 massJARM.py --help
```

## 📖 Usage

### Basic Examples

```bash
# Scan a single target on default SSL ports
python3 massJARM.py -t example.com

# Scan a single target on a specific port
python3 massJARM.py -t example.com:8443

# Scan targets from a file
python3 massJARM.py -i targets.txt

# Save results to CSV
python3 massJARM.py -i targets.txt -o results.csv
```

### Advanced Examples

```bash
# Use 10 threads with rate limiting (50 requests/second/thread)
python3 massJARM.py -i targets.txt --threads 10 --rate 50 -o results.csv

# Scan custom ports
python3 massJARM.py -i targets.txt --ports 443 8443 8080 9443

# Set custom timeout on the socket connection (30 seconds)
python3 massJARM.py -i targets.txt --timeout 30
```

### Command Line Options

```
usage: massJARM.py [-h] (-t TARGET | -i INPUT) [-o OUTPUT] [--threads THREADS] [--rate RATE] [--timeout TIMEOUT]
                   [--ports PORTS [PORTS ...]]

massJARM - TLS fingerprinting tool

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single target (domain or IP, with optional port)
  -i INPUT, --input INPUT
                        Input file with targets (one per line)
  -o OUTPUT, --output OUTPUT
                        Output CSV file (default: stdout)
  --threads THREADS     Number of threads (default: 5)
  --rate RATE           Max requests per second per thread (0=unlimited)
  --timeout TIMEOUT     Socket timeout in seconds (default: 20)
  --ports PORTS [PORTS ...]
                        Custom ports to try if none specified

Examples:
  massJARM.py -t example.com
  massJARM.py -t example.com:8443
  massJARM.py -i targets.txt -o results.csv
  massJARM.py -i targets.txt --threads 10 --rate 50
```

## 📁 Input File Format

The input file supports various formats, one target per line:

```
# Domains without ports (will scan default SSL ports)
example.com
google.com
cloudflare.com

# IPs without ports
192.168.1.1
8.8.8.8

# Specific ports
example.com:8443
192.168.1.1:443
localhost:4443

# Mixed format in the same file
example.com
192.168.1.1:8080
google.com:443
```

### Default SSL/TLS Ports

If no port is specified, the scanner will try these common SSL/TLS ports:
- 443 (HTTPS)
- 8443 (HTTPS alternate)
- 8080 (HTTP/HTTPS alternate)
- 8000 (HTTP alternate)

## 🔍 JARM Process

The JARM fingerprinting process involves:

1. **Probe Generation**: Create 10 different TLS Client Hello messages with varying:
   - TLS versions (1.0, 1.1, 1.2, 1.3)
   - Cipher suites (different orders and selections)
   - Extensions (ALPN, SNI, etc.)
   - GREASE values

2. **Connection & Data Collection**: For each probe:
   - Establish TCP connection
   - Send Client Hello
   - Receive Server Hello (up to 1484 bytes)
   - Extract cipher suite, TLS version, and extensions

3. **Hash Calculation**: 
   - Combine responses from all 10 probes
   - Apply custom fuzzy hashing algorithm
   - Generate 62-character JARM fingerprint

## 🎯 Known C2 JARM Signatures

Search for known Command & Control (C2) server signatures:

```bash
# Common C2 JARM fingerprints
cat results.csv | grep -E "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1|\
07d14d16d21d21d07c42d43d000000f50d155305214cf247147c43c0f1a823|\
07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d|\
2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb|\
21d14d00000000021c21d14d21d21d1ee8ae98bf3ef941e91529a93ac62b8b|\
29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38|\
00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64|\
2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261|\
20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6|\
2ad2ad0002ad2ad00041d2ad2ad41da5207249a18099be84ef3c8811adc883|\
2ad000000000000000000000000000eeebf944d0b023a00f510f06a29b4f46|\
22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9"
```

For more C2 JARM signatures, see: [C2-JARM Repository](https://github.com/cedowens/C2-JARM)

## ⚡ Performance

Performance comparison with different thread counts (scanning 500 targets):

| Tool | Threads | Time | Improvement |
|------|---------|------|-------------|
| Original JARM | 1 | 1049s | - |
| Threaded Scanner | 5 (default) | ~210s | 5x faster |
| Threaded Scanner | 10 | ~105s | 10x faster |
| Threaded Scanner | 20 | ~52s | 20x faster |

*Note: Actual performance depends on network conditions and target response times*

### Performance Tips

1. **Thread Count**: Start with 10-20 threads for optimal performance
2. **Rate Limiting**: Use `--rate` to avoid overwhelming targets or your network
3. **Timeout**: Adjust `--timeout` based on network conditions (lower for LAN, higher for WAN)
4. **Port Selection**: Specify exact ports when known to avoid scanning unnecessary ports

## 🛡️ Responsible Use

This tool is intended for:
- Network security assessments
- Asset identification
- Security research
- Compliance checking

Please ensure you have permission to scan target systems. Unauthorized scanning may violate laws and terms of service.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📚 References

- [Original JARM by Salesforce](https://github.com/salesforce/jarm)
- [JARM Technical Blog Post](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a)
- [C2 JARM Signatures](https://github.com/cedowens/C2-JARM)

## 📜 License

See LICENSE file

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.