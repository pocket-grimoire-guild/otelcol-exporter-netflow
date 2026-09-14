//go:build ignore

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

func main() {
	manifest := flag.String("manifest", "integration/testdata/pcap/payload-manifest.yaml", "authored payload inventory")
	root := flag.String("pcap-root", "integration/testdata/pcap", "PCAP directory")
	goldens := flag.String("golden-manifest", "integration/testdata/golden/manifest.json", "existing golden manifest")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if err := fixturepcap.Verify(*manifest, *goldens, *root); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS: seven one-to-one golden payload lengths/hashes and synthetic IPv4/UDP checksums")
}
