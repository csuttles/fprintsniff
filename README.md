# fprintsniff

This is a way grab tls fingerpint info (ja3/ja3s) from TLS straffic.

The name is the basic idea. A connection is made, this program grabs the fingerprint from the sniffed data

## install
clone this repo
`git submodule update --init --recursive`
python3 -m venv --copies venv
. ./venv/bin/activate
pip install scapy dpkt
run the tool

### serve a pixel to sniff

http://png-pixel.com/

Embed PNG pixels directly in your source code
If you don't like having small 1x1 pixel images in your projects, you can embed the base64 encoded pixel directly in your css or html source files.
HTML
```
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=">
```
If you don't need color or alpha you could use a fully transparent 1x1 GIF pixel to save a few more bytes.
Transparent 1x1 GIF pixel
```
<img src="data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==">
```

Normally, you want to set up this pixel to get fetched by including it in your ad or site etc that you want to get more information.
We're going to serve it directly and focus on what we can grab from that simple GET for client fingerprinting.

## sniff traffic

This is how we grab the raw data about the connection.

### turn traffic into a fingerprint

The next step is to identify and strip out the attributes we want from the packets we captured, and turn that data into a fingerprint.

### OK what is a fingerprint

Right now just an idea, but eventually this will be a data structure, like a struct or rpc message that can be shipped via event bus or stored in a k/v store or db,
and used to make decisions about defense. Here's a great example of some things we can do to grab a fingerprint and what the data might look like:

https://isc.sans.edu/forums/diary/Browser+Fingerprinting+via+SSL+Client+Hello+Messages/17210

An example might look like:

```
"ip": 10.10.10.10
"user-agent": ctlfish
"Cipher-Suites": 0x00ff,0xc00a,0xc014,0x0088,0x0087,0x0039,0x0038,0xc00f,0xc005,0x0084,0x0035,0xc007,0xc009,0xc011,0xc013,0x0045,0x0044,0x0033,0x0032,0xc00c,0xc00e,0xc002,0xc004,0x0096,0x0041,0x0005,0x0004,0x002f,0xc008,0xc012,0x0016,0x0013,0xc00d,0xc003,0xfeff,0x000a
"SSL-Version": 0x0301 (TLS 1.0)
"Extensions": 0x0301 0x0000,0x000a,0x000b,0x0023,0x3374
```

### fingerprints are really made of

ja3 and ja3s already exist and do this, so I just used those. Thanks! :D

#### capture example using tls filters

The linked example filters are for older versions of wireshark/tshark; here's an example that will work with newer versions (tls dissector not ssl).

```
kali@jabroni:[~/src/pixelprint]:(master *+)
[Exit: 0] 13:30: sudo tshark -i en0 -nn -T fields -e ip.src -e tls.handshake.ciphersuite -e tls.handshake.version -e tls.handshake.extension.type -e tls.handshake.extensions_server_name -Y "tls.handshake"
```
