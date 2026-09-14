//go:build ignore

// Run from the repository root; generated PCAPs are disposable test outputs.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/integration/tshark/internal/fixturepcap"
)

func main() {
	goldens := flag.String("golden-manifest", "integration/testdata/golden/manifest.json", "existing golden manifest")
	manifest := flag.String("manifest", "integration/testdata/pcap/payload-manifest.yaml", "authored payload inventory")
	out := flag.String("out", "integration/testdata/pcap", "generated PCAP directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if err := fixturepcap.Generate(*manifest, *goldens, *out); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS: wrapped and verified all seven immutable golden UDP payloads (synthetic outer headers)")
}
