package mapping

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	staticmapping "github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/mapping"
	"github.com/pocket-grimoire-guild/otelcol-exporter-netflow/internal/wire"
)

const (
	manifestSchema      = "otel-netflow-mapping-coverage"
	manifestVersion     = 1
	manifestFingerprint = "8b890b8dd63790803dcd7f350a39867eae6d19ca2ecf438540a41160dc1d114a"
)

type manifestSource struct {
	ID      string `json:"id"`
	Contrib string `json:"contrib_commit,omitempty"`
	Goflow2 string `json:"goflow2_commit,omitempty"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

type manifestRef struct {
	Row    int `json:"row"`
	Column int `json:"column"`
}

type manifestCell struct {
	Attribute      string      `json:"attribute"`
	Protocol       string      `json:"protocol"`
	Classification []string    `json:"classification"`
	MatrixRef      manifestRef `json:"matrix_ref"`
	Outcome        string      `json:"outcome"`
	OutcomeSHA256  string      `json:"outcome_sha256"`
	TestID         string      `json:"test_id"`
}

type registryCell struct {
	Attribute      string
	Protocol       string
	Classification []string
	MatrixRef      manifestRef
	OutcomeSHA256  string
	TestID         string
}

type manifestCanonical struct {
	Attributes  []string       `json:"attributes"`
	Protocols   []string       `json:"protocols"`
	Cells       []manifestCell `json:"cells"`
	Fingerprint string         `json:"fingerprint"`
}

type manifestDocument struct {
	Schema  string `json:"schema"`
	Version int    `json:"version"`
	Sources struct {
		Receiver manifestSource `json:"receiver_profile"`
		Matrix   manifestSource `json:"matrix"`
	} `json:"sources"`
	Canonical manifestCanonical `json:"canonical"`
	Extras    map[string]struct {
		TestID string `json:"test_id"`
	} `json:"extras"`
}

// manifestRegistry is intentionally a literal 123-case registry. It is an
// independent review surface: the checker derives its expected matrix from
// the pinned documents, while this registry binds every stable Go subtest.
var manifestRegistry = []registryCell{
	{Attribute: "source.address", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 1, Column: 1}, OutcomeSHA256: "022f55cd6a6967149878c3a0a3f49c745a58c2c981cc8a1bef2fc285d08e9b4a", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/source.address"},
	{Attribute: "source.address", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 1, Column: 2}, OutcomeSHA256: "88ee2c082bb708b92c183b79475af2e4dded55e21ea5ccad24de4b6be79caa21", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/source.address"},
	{Attribute: "source.address", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 1, Column: 3}, OutcomeSHA256: "3a0b20f4d9615e745643af1ef121f64d658e656bbd7040985cf75ab1a1ffe9b0", TestID: "integration/mapping:TestManifestCoverage/ipfix/source.address"},
	{Attribute: "source.port", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 2, Column: 1}, OutcomeSHA256: "d7d20fff4684ed749e1050a826eca5c32dc43c67ed45d4f6284f61a224680d1e", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/source.port"},
	{Attribute: "source.port", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 2, Column: 2}, OutcomeSHA256: "8909d21e1614103eba45b35d4d08f1095712e8cd1afb6c61673395c84bb6cf56", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/source.port"},
	{Attribute: "source.port", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 2, Column: 3}, OutcomeSHA256: "e8a567c458b7ce2f47c7abddcf2b5d68c678410e73da9228158e33cde55197f1", TestID: "integration/mapping:TestManifestCoverage/ipfix/source.port"},
	{Attribute: "destination.address", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 3, Column: 1}, OutcomeSHA256: "426a6f542139c0fd4953b8f2a4965ee07bf275261077c7756cd40fdc549c96a7", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/destination.address"},
	{Attribute: "destination.address", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 3, Column: 2}, OutcomeSHA256: "606e78ee4db5f89fbda48b06d05dfdc7103e3714e826ca624da9af22ecc42211", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/destination.address"},
	{Attribute: "destination.address", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 3, Column: 3}, OutcomeSHA256: "0ef8f18a7158cb18b5fec2b595a3b9fad5b3c60bdb904339270852d707d77275", TestID: "integration/mapping:TestManifestCoverage/ipfix/destination.address"},
	{Attribute: "destination.port", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 4, Column: 1}, OutcomeSHA256: "acdec9ab6713a2073d6cd5b510f598ac7ef2d0016042168ff5b2d40a7c7e1fde", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/destination.port"},
	{Attribute: "destination.port", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 4, Column: 2}, OutcomeSHA256: "895a65e9350878ee6e16dda8b8b3632d4b603ae4e320e35712eddcaf28612e11", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/destination.port"},
	{Attribute: "destination.port", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 4, Column: 3}, OutcomeSHA256: "4b37f8c8a18e3b0b5c2c2411fbbf54bf8ac28c2e981350fe84e9fa2b6a8eff69", TestID: "integration/mapping:TestManifestCoverage/ipfix/destination.port"},
	{Attribute: "network.transport", Protocol: "netflow_v5", Classification: []string{"synthesized"}, MatrixRef: manifestRef{Row: 5, Column: 1}, OutcomeSHA256: "af6d7ac8677ca95bc084c0985dee77a30014042364a2af391c75c4ef31cc10fa", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/network.transport"},
	{Attribute: "network.transport", Protocol: "netflow_v9", Classification: []string{"synthesized"}, MatrixRef: manifestRef{Row: 5, Column: 2}, OutcomeSHA256: "cce96dd51fbde255e717c91409893f4cab61ca2a20444525dec7a194eec5ce27", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/network.transport"},
	{Attribute: "network.transport", Protocol: "ipfix", Classification: []string{"synthesized"}, MatrixRef: manifestRef{Row: 5, Column: 3}, OutcomeSHA256: "63a1465da28a1b0aac8fbf2522036a1b5ccd9e6b3ee051a7a5fcc7aafadca337", TestID: "integration/mapping:TestManifestCoverage/ipfix/network.transport"},
	{Attribute: "network.type", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 6, Column: 1}, OutcomeSHA256: "d1a1fb0d6703fac6ead44bd30f19a5b8134c9705230dccd288a3926e49ac6e84", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/network.type"},
	{Attribute: "network.type", Protocol: "netflow_v9", Classification: []string{"synthesized"}, MatrixRef: manifestRef{Row: 6, Column: 2}, OutcomeSHA256: "468b5a5d4187ad36c5cf5153b7e46a42c1a80199d9c8bab875df96da46281e3a", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/network.type"},
	{Attribute: "network.type", Protocol: "ipfix", Classification: []string{"synthesized", "unsupported"}, MatrixRef: manifestRef{Row: 6, Column: 3}, OutcomeSHA256: "b1cf0e4b2c2dad3836872eba6dd072c1efae3fc8741ff4afc278ae5921fa9706", TestID: "integration/mapping:TestManifestCoverage/ipfix/network.type"},
	{Attribute: "flow.io.bytes", Protocol: "netflow_v5", Classification: []string{"lossy", "unsupported"}, MatrixRef: manifestRef{Row: 7, Column: 1}, OutcomeSHA256: "2df20369686a17f3b85979d55a1cbcf23aa6800ea8a1a344920a084010768a89", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.io.bytes"},
	{Attribute: "flow.io.bytes", Protocol: "netflow_v9", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 7, Column: 2}, OutcomeSHA256: "67159f3534cd73faac9a42cf5a3e297dafcd90f4d38c1fa216c978140218815d", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.io.bytes"},
	{Attribute: "flow.io.bytes", Protocol: "ipfix", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 7, Column: 3}, OutcomeSHA256: "eb907902c1b23f99fd7a698aee0999d073dd58cbf8492058a5d42c5107d0c755", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.io.bytes"},
	{Attribute: "flow.io.packets", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 8, Column: 1}, OutcomeSHA256: "012535b963ed9784cf03690a01abe380dc0c5b34a27fe44300d52deae6729b58", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.io.packets"},
	{Attribute: "flow.io.packets", Protocol: "netflow_v9", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 8, Column: 2}, OutcomeSHA256: "96e7273d9dfa37d3f3f1304adf8e68325a18976e08a2c16c968e095e975cb579", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.io.packets"},
	{Attribute: "flow.io.packets", Protocol: "ipfix", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 8, Column: 3}, OutcomeSHA256: "a1f2e83bd6a05c53430bac88a3da6463ff49dcc529eb729484835918afc95d07", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.io.packets"},
	{Attribute: "flow.type", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 9, Column: 1}, OutcomeSHA256: "2c5c33c41d9283c99e60b1da75232a968a69b8aa2b1b433ccb43151cce915f3e", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.type"},
	{Attribute: "flow.type", Protocol: "netflow_v9", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 9, Column: 2}, OutcomeSHA256: "692241f50fa6fa8d7da67067257bcfd943583f58a6875e363e5225b968f2bf04", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.type"},
	{Attribute: "flow.type", Protocol: "ipfix", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 9, Column: 3}, OutcomeSHA256: "567df7f09200fc9f9ee0e8af332f8a9069c54e444d529bb41a032bd1dabd1e22", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.type"},
	{Attribute: "flow.sequence_num", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 10, Column: 1}, OutcomeSHA256: "c6058455d77a4f767c4dfa3c169d0174a44865265792bc878ebb7d880f58c116", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.sequence_num"},
	{Attribute: "flow.sequence_num", Protocol: "netflow_v9", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 10, Column: 2}, OutcomeSHA256: "886c2420eade595d22d0889ef70014aea424d68121258228b174b74b493911cf", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.sequence_num"},
	{Attribute: "flow.sequence_num", Protocol: "ipfix", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 10, Column: 3}, OutcomeSHA256: "cfbe4a2e085f73deeaf2fdf72d95fddf9749618063b61f5354d9f6819f5c6c00", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.sequence_num"},
	{Attribute: "flow.time_received", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 11, Column: 1}, OutcomeSHA256: "727916843dd43b23260fcfae46c663a28dd9645508e8e5dd599b41afe0765c3d", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.time_received"},
	{Attribute: "flow.time_received", Protocol: "netflow_v9", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 11, Column: 2}, OutcomeSHA256: "4f39b225358b968a278e56f3e580c6ffe4a7e881442911853688a7e0001b52eb", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.time_received"},
	{Attribute: "flow.time_received", Protocol: "ipfix", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 11, Column: 3}, OutcomeSHA256: "6052261b09bf557e7a46c5a3de34165de18ba4c5473fdfd72255b3eff79bcab2", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.time_received"},
	{Attribute: "flow.start", Protocol: "netflow_v5", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 12, Column: 1}, OutcomeSHA256: "1e4d4800badf1789838123fd12c2e8510f8fcd8b4311dc763156f2b6ef78e6f8", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.start"},
	{Attribute: "flow.start", Protocol: "netflow_v9", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 12, Column: 2}, OutcomeSHA256: "e156680677b3e110b153702f59cb55fcac17f2f796e1f23ba08a3c0d7e8b2a86", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.start"},
	{Attribute: "flow.start", Protocol: "ipfix", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 12, Column: 3}, OutcomeSHA256: "10769ed7dcdcd3a74d31da540e85122c7cf3aa8bb5731ee57fad65ef97a82d2b", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.start"},
	{Attribute: "flow.end", Protocol: "netflow_v5", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 13, Column: 1}, OutcomeSHA256: "1dbf18cd0e6a42b4af89f8067695bdd0f745d296672ff83d2a69dffc018fde5f", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.end"},
	{Attribute: "flow.end", Protocol: "netflow_v9", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 13, Column: 2}, OutcomeSHA256: "096db2bdb4bab98a56158c8d2205f0bf39e9ac7a8bf5186f370aff9a47117854", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.end"},
	{Attribute: "flow.end", Protocol: "ipfix", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 13, Column: 3}, OutcomeSHA256: "c86a4ba84e3543132251dc4517998527afe2c1a4dd709e9be45596591f9f0d6a", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.end"},
	{Attribute: "flow.sampling_rate", Protocol: "netflow_v5", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 14, Column: 1}, OutcomeSHA256: "1e1b1fd39ac4947d2395f41aba3c2f76122592cfc807e179934c3dc2d467f8d9", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.sampling_rate"},
	{Attribute: "flow.sampling_rate", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 14, Column: 2}, OutcomeSHA256: "74abc9c46c665699a28d85a9b788fcea22158357e059b089509b92bdc0a54712", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.sampling_rate"},
	{Attribute: "flow.sampling_rate", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 14, Column: 3}, OutcomeSHA256: "49633e816e16f6ac7f6d98f0d3f6ed60580528bf1ad168c9f8cf07c44949008d", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.sampling_rate"},
	{Attribute: "flow.sampler_address", Protocol: "netflow_v5", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 15, Column: 1}, OutcomeSHA256: "a0e595b255e7f80a058d87b28c9348a536fda4a947793d42b3b43b8121a6b5fb", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.sampler_address"},
	{Attribute: "flow.sampler_address", Protocol: "netflow_v9", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 15, Column: 2}, OutcomeSHA256: "8b2ec48ed3991904747b7af0a591e37c35193d37352bc01143f1f05a5186cc9b", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.sampler_address"},
	{Attribute: "flow.sampler_address", Protocol: "ipfix", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 15, Column: 3}, OutcomeSHA256: "1df88f3dffdf289369484ec79d1e49d84806d753e1a6ad6f3a7cc02898c1bea7", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.sampler_address"},
	{Attribute: "flow.tcp_flags", Protocol: "netflow_v5", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 16, Column: 1}, OutcomeSHA256: "194527e6797a290161c6cd64e099a90de7082daeb86cb620770b253c6f185d5b", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.tcp_flags"},
	{Attribute: "flow.tcp_flags", Protocol: "netflow_v9", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 16, Column: 2}, OutcomeSHA256: "dfafad74ced54a42ad4bac16611818fd7e313616bfee56be4c562dbdf602f069", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.tcp_flags"},
	{Attribute: "flow.tcp_flags", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 16, Column: 3}, OutcomeSHA256: "c05739c92d89acaa7a79c371ab9591b47e2bcc5b64b6751d406c7e3e5a56e12c", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.tcp_flags"},
	{Attribute: "flow.in_if", Protocol: "netflow_v5", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 17, Column: 1}, OutcomeSHA256: "cb059e9a53e8d72184c32c1faa7f1b7883481ca772de3937e9311ef475bc7003", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.in_if"},
	{Attribute: "flow.in_if", Protocol: "netflow_v9", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 17, Column: 2}, OutcomeSHA256: "4d12cecf26754b0488920e13c45773cc25bf5fb2acd7523315772b42117a2d69", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.in_if"},
	{Attribute: "flow.in_if", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 17, Column: 3}, OutcomeSHA256: "935df77012741f472064b85dcf64f5efe5371ec5cf4705cea0f3dff2fd537141", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.in_if"},
	{Attribute: "flow.out_if", Protocol: "netflow_v5", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 18, Column: 1}, OutcomeSHA256: "7da99d1f177ce20e7546d1f6f2c3978ff7423bde75c72a06aa05e4b964718903", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.out_if"},
	{Attribute: "flow.out_if", Protocol: "netflow_v9", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 18, Column: 2}, OutcomeSHA256: "07cecd96895a64d30ef0043e811d1858d88e976601fc97c7878b7111217a03f1", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.out_if"},
	{Attribute: "flow.out_if", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 18, Column: 3}, OutcomeSHA256: "0523024fe7842212982ef5bb2497b9ec7255fec2816d7337a0d7afe0bce24fdb", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.out_if"},
	{Attribute: "flow.ip_tos", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 19, Column: 1}, OutcomeSHA256: "179371f300bbd027bb1eb7469f1c6818fc78954956ef92446588cb4baa902903", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.ip_tos"},
	{Attribute: "flow.ip_tos", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 19, Column: 2}, OutcomeSHA256: "a35824b26190794ae26ffa47e1e6c12e90f309b2c89fe407bc09b1d4e78cb01c", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.ip_tos"},
	{Attribute: "flow.ip_tos", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 19, Column: 3}, OutcomeSHA256: "40754352067e69bed4d6bf1ea9f8196a2964d8842530302fe8d4808468de9b39", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.ip_tos"},
	{Attribute: "flow.ip_ttl", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 20, Column: 1}, OutcomeSHA256: "bb2d46932a35f7f4cd58b0607062087d99e854ee2f04c7d4b1010995fcfa05d5", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.ip_ttl"},
	{Attribute: "flow.ip_ttl", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 20, Column: 2}, OutcomeSHA256: "964de3b47cfbbd3654bea63c8544be2cd0f33e99458fb9545f92bd3b6603038d", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.ip_ttl"},
	{Attribute: "flow.ip_ttl", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 20, Column: 3}, OutcomeSHA256: "db2426b572d847ba7307ca2aa13dcd889c3dc36159d5fc2c970bdc20e41dd4b9", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.ip_ttl"},
	{Attribute: "flow.ip_flags", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 21, Column: 1}, OutcomeSHA256: "bb2d46932a35f7f4cd58b0607062087d99e854ee2f04c7d4b1010995fcfa05d5", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.ip_flags"},
	{Attribute: "flow.ip_flags", Protocol: "netflow_v9", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 21, Column: 2}, OutcomeSHA256: "8310919efe310dd8af720f4ac4a6af46e34422b2556de2ba1c34dc113e01bcda", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.ip_flags"},
	{Attribute: "flow.ip_flags", Protocol: "ipfix", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 21, Column: 3}, OutcomeSHA256: "2eeac67bb023807d1469c8f9fae25573a7591cd4b7a0a2411ff6c7ef443da69b", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.ip_flags"},
	{Attribute: "flow.fragment_id", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 22, Column: 1}, OutcomeSHA256: "bb2d46932a35f7f4cd58b0607062087d99e854ee2f04c7d4b1010995fcfa05d5", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.fragment_id"},
	{Attribute: "flow.fragment_id", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 22, Column: 2}, OutcomeSHA256: "952906cc4f7f33ee9a3b9c5eee366ee33c4ceca3e340ad9b1db644a218b1fd6e", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.fragment_id"},
	{Attribute: "flow.fragment_id", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 22, Column: 3}, OutcomeSHA256: "60cedfa2779307fbb2a355d99bb85c8736b648e1b9e7daacf075d700b312470d", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.fragment_id"},
	{Attribute: "flow.fragment_offset", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 23, Column: 1}, OutcomeSHA256: "bb2d46932a35f7f4cd58b0607062087d99e854ee2f04c7d4b1010995fcfa05d5", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.fragment_offset"},
	{Attribute: "flow.fragment_offset", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 23, Column: 2}, OutcomeSHA256: "164531f3dabc1a7e13287bc1e0df11242402de5d020cd6368fc67e3c6f12ae41", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.fragment_offset"},
	{Attribute: "flow.fragment_offset", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 23, Column: 3}, OutcomeSHA256: "1416aada968f0c2801aa1cd092375d406803d12e3ec8ad2145a266715e615d79", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.fragment_offset"},
	{Attribute: "flow.ipv6_flow_label", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 24, Column: 1}, OutcomeSHA256: "bb2d46932a35f7f4cd58b0607062087d99e854ee2f04c7d4b1010995fcfa05d5", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.ipv6_flow_label"},
	{Attribute: "flow.ipv6_flow_label", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 24, Column: 2}, OutcomeSHA256: "20066b994c1541f7ed8dbeffe614fb3b8d7563a6e9ee4edf305f25865906a75b", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.ipv6_flow_label"},
	{Attribute: "flow.ipv6_flow_label", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 24, Column: 3}, OutcomeSHA256: "ccb41363e81c7d5e6fc2bf952b4a9cf97bb3f770d11d4b9cb406bd42c96494f8", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.ipv6_flow_label"},
	{Attribute: "flow.icmp_type", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 25, Column: 1}, OutcomeSHA256: "dc2a22d20b4f31eedf8a08e81941fd640ee7d860bc1149accfee6cdbc88ff086", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.icmp_type"},
	{Attribute: "flow.icmp_type", Protocol: "netflow_v9", Classification: []string{"synthesized"}, MatrixRef: manifestRef{Row: 25, Column: 2}, OutcomeSHA256: "da1d0e4a8fa43604e72663a7351535617f8be18dd29bb5534162d6849e7beaa6", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.icmp_type"},
	{Attribute: "flow.icmp_type", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 25, Column: 3}, OutcomeSHA256: "3f97f050c11fdb3f1a435979e96ca349578381d6af637540eaaa4b63613b70a9", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.icmp_type"},
	{Attribute: "flow.icmp_code", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 26, Column: 1}, OutcomeSHA256: "dc2a22d20b4f31eedf8a08e81941fd640ee7d860bc1149accfee6cdbc88ff086", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.icmp_code"},
	{Attribute: "flow.icmp_code", Protocol: "netflow_v9", Classification: []string{"synthesized"}, MatrixRef: manifestRef{Row: 26, Column: 2}, OutcomeSHA256: "c0b28cd8eac04105934bc8f576d84b5c7fd6aebb07e92ea451a3bd7868e2c83b", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.icmp_code"},
	{Attribute: "flow.icmp_code", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 26, Column: 3}, OutcomeSHA256: "617f7bb558c8be0dff10a375f36038cdcfa4b9476ed17db5e8dec0f9619c0077", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.icmp_code"},
	{Attribute: "flow.src_mac", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 27, Column: 1}, OutcomeSHA256: "d892275d7b220463fa088ebac372d2a5d4cfd1714709d336c8009ecc6040c167", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.src_mac"},
	{Attribute: "flow.src_mac", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 27, Column: 2}, OutcomeSHA256: "a3a50340a5244c840b3bbb4f5c02c5c3bf84c041566f3b9e60793901a34d1831", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.src_mac"},
	{Attribute: "flow.src_mac", Protocol: "ipfix", Classification: []string{"lossy", "unsupported"}, MatrixRef: manifestRef{Row: 27, Column: 3}, OutcomeSHA256: "a6791f40c165112140d1c0c9aa9d0d58f38880b1b6f41ccab6c2a788f5d1e95b", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.src_mac"},
	{Attribute: "flow.dst_mac", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 28, Column: 1}, OutcomeSHA256: "d892275d7b220463fa088ebac372d2a5d4cfd1714709d336c8009ecc6040c167", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.dst_mac"},
	{Attribute: "flow.dst_mac", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 28, Column: 2}, OutcomeSHA256: "f1d2b561bbf1a10b14ef99cff5437a17d72b4774cce6a6f49849801ca4823ad7", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.dst_mac"},
	{Attribute: "flow.dst_mac", Protocol: "ipfix", Classification: []string{"lossy", "unsupported"}, MatrixRef: manifestRef{Row: 28, Column: 3}, OutcomeSHA256: "1cc34f5e39cd38326280ff66da829813055095e8214c7fca2354f305938ee64e", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.dst_mac"},
	{Attribute: "flow.src_vlan", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 29, Column: 1}, OutcomeSHA256: "797e05b2ccbb285d5f1e3f23943d38553b43eb1bd821915bed9361650dd49d14", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.src_vlan"},
	{Attribute: "flow.src_vlan", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 29, Column: 2}, OutcomeSHA256: "10a8204cdbf22097d74a3bf22f551e2ad36ae526462ff53c9f491acb674eb2f8", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.src_vlan"},
	{Attribute: "flow.src_vlan", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 29, Column: 3}, OutcomeSHA256: "19d00552d2587e23b0f3cf9d80e2590ac7124432d35f1096cca551bbae3081e9", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.src_vlan"},
	{Attribute: "flow.dst_vlan", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 30, Column: 1}, OutcomeSHA256: "797e05b2ccbb285d5f1e3f23943d38553b43eb1bd821915bed9361650dd49d14", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.dst_vlan"},
	{Attribute: "flow.dst_vlan", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 30, Column: 2}, OutcomeSHA256: "db099aa22885e299a745a7fabc348951a50dc9f8f5c58edfca6c80e8a8357b6a", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.dst_vlan"},
	{Attribute: "flow.dst_vlan", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 30, Column: 3}, OutcomeSHA256: "d3369e5ddef5e36f043141ae01fe6468934b1df3ae210b5b7dc216c6ccba3d3e", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.dst_vlan"},
	{Attribute: "flow.vlan_id", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 31, Column: 1}, OutcomeSHA256: "797e05b2ccbb285d5f1e3f23943d38553b43eb1bd821915bed9361650dd49d14", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.vlan_id"},
	{Attribute: "flow.vlan_id", Protocol: "netflow_v9", Classification: []string{"lossy", "synthesized"}, MatrixRef: manifestRef{Row: 31, Column: 2}, OutcomeSHA256: "1e518c2e8fea0966622721e722c4197b8809ca4ba93186785ecd59e3e5927c64", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.vlan_id"},
	{Attribute: "flow.vlan_id", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 31, Column: 3}, OutcomeSHA256: "57a0bfa07aeca5984339ab70fefd5994e796daf64083609d081a31f998c146fd", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.vlan_id"},
	{Attribute: "flow.next_hop", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 32, Column: 1}, OutcomeSHA256: "a64c834abb4a3f9cb99a42c3b6106e3d2cbf57f18e16cb235f1a4f1608f83a84", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.next_hop"},
	{Attribute: "flow.next_hop", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 32, Column: 2}, OutcomeSHA256: "e51bcda60b96627337edca49a8555df40e653c1008b52aa0bba151f196b01d19", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.next_hop"},
	{Attribute: "flow.next_hop", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 32, Column: 3}, OutcomeSHA256: "dd225cfa997edc987cf1ed44704936325d54cffb5a95586fdbe37432f92b645d", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.next_hop"},
	{Attribute: "flow.next_hop_as", Protocol: "netflow_v5", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 33, Column: 1}, OutcomeSHA256: "f727fb7a58cea6167f8f8b4ece5fa29c4bf86b06eab8a8f8af9d8ef9bf2c4d3b", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.next_hop_as"},
	{Attribute: "flow.next_hop_as", Protocol: "netflow_v9", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 33, Column: 2}, OutcomeSHA256: "4fa76cac116025d685260ceb1915e5669e4557c93da3f6315c39ebb1d5f1cc72", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.next_hop_as"},
	{Attribute: "flow.next_hop_as", Protocol: "ipfix", Classification: []string{"unsupported"}, MatrixRef: manifestRef{Row: 33, Column: 3}, OutcomeSHA256: "33ab7b0aada04607f7a5dea4ce3db61ee7b567d2fba5575d1885954d5fbd0aa6", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.next_hop_as"},
	{Attribute: "flow.src_as", Protocol: "netflow_v5", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 34, Column: 1}, OutcomeSHA256: "4b7c3a83e0b5b9188a7bbc5341fd72bd4f86daf6b995b4021b1d736830501196", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.src_as"},
	{Attribute: "flow.src_as", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 34, Column: 2}, OutcomeSHA256: "7794411d54c67f54700a078f2d0acbbb90582124530a0f482e39dee7d9115351", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.src_as"},
	{Attribute: "flow.src_as", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 34, Column: 3}, OutcomeSHA256: "3081696e645329ffe7b7ceaafb929045be18ed35aecfeb6c9132848ea78afd5a", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.src_as"},
	{Attribute: "flow.dst_as", Protocol: "netflow_v5", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 35, Column: 1}, OutcomeSHA256: "1d73f7e75ad2b091add2f7bd3d2be837f4a8dba09c4d6d5c262fcef5cfb6f53e", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.dst_as"},
	{Attribute: "flow.dst_as", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 35, Column: 2}, OutcomeSHA256: "e68a7c6797ab6089c729451e665a959630385af6dcccd9e7883c48597b1a2d6a", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.dst_as"},
	{Attribute: "flow.dst_as", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 35, Column: 3}, OutcomeSHA256: "fa051fd71d65cc7f0980fc0211e1596faab33678c8ef254378df60dacf964db2", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.dst_as"},
	{Attribute: "flow.bgp_next_hop", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 36, Column: 1}, OutcomeSHA256: "9ccefdc34646b2cee66f4365ea1cb1d69a1e526f04a76ac3c8ea89e7ffe9ae76", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.bgp_next_hop"},
	{Attribute: "flow.bgp_next_hop", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 36, Column: 2}, OutcomeSHA256: "29159a3c8b2fbec405fa374037de43dc604b7dfedbf7bfd97b1f3ef2d5b296ef", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.bgp_next_hop"},
	{Attribute: "flow.bgp_next_hop", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 36, Column: 3}, OutcomeSHA256: "6275f6f13eedf42709923801a7329933d75bda0d6b08fee36b2e19cd0a0aaaa3", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.bgp_next_hop"},
	{Attribute: "flow.src_net", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 37, Column: 1}, OutcomeSHA256: "19fc40212b46b5b3d9dd2814d9cfffc7f3ca1468ba19a95d8dd5fac717556375", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.src_net"},
	{Attribute: "flow.src_net", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 37, Column: 2}, OutcomeSHA256: "031acfe1a8bae71da79c92812b62fd238cd06c718e25aa05600d0095f6d0da28", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.src_net"},
	{Attribute: "flow.src_net", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 37, Column: 3}, OutcomeSHA256: "58df70d139626f241334fe61edf033ff4484b7c13c1a715edd718f1daae8da14", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.src_net"},
	{Attribute: "flow.dst_net", Protocol: "netflow_v5", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 38, Column: 1}, OutcomeSHA256: "d96d69c5173da5b823eaf3aef8528e3579973a3cdffb72eaaceb0128fa760dc5", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.dst_net"},
	{Attribute: "flow.dst_net", Protocol: "netflow_v9", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 38, Column: 2}, OutcomeSHA256: "dc5598b3f354dd7ce1e68d0f2d804c41f770df1772fa6085be1c72980aa8fe79", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.dst_net"},
	{Attribute: "flow.dst_net", Protocol: "ipfix", Classification: []string{"exact"}, MatrixRef: manifestRef{Row: 38, Column: 3}, OutcomeSHA256: "806a9dddcafcb418a0663e35e5d385cb27288195281488309df4cdfbb46df43c", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.dst_net"},
	{Attribute: "flow.forwarding_status", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 39, Column: 1}, OutcomeSHA256: "f64167b8152f3ef35a49bf5bd7a86325f71695577a61e4a6b01388f3ddd84876", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.forwarding_status"},
	{Attribute: "flow.forwarding_status", Protocol: "netflow_v9", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 39, Column: 2}, OutcomeSHA256: "13bf187a01aad295df3175312f2aeb835c5dccde4dd3141ecead995a60575067", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.forwarding_status"},
	{Attribute: "flow.forwarding_status", Protocol: "ipfix", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 39, Column: 3}, OutcomeSHA256: "c9fc2706add8ae2378b84a6831cc0cd5c7cc9285da78fa9d8b2b07c5fab08636", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.forwarding_status"},
	{Attribute: "flow.observation_domain_id", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 40, Column: 1}, OutcomeSHA256: "d68e02eca800d9c6c44f073b458789b7516ca03eddbee2de9cca4873539b89c3", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.observation_domain_id"},
	{Attribute: "flow.observation_domain_id", Protocol: "netflow_v9", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 40, Column: 2}, OutcomeSHA256: "25a5f3a920d8e4626ab2b40f732de6a1e555739a744bf349ce837e908d9754c4", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.observation_domain_id"},
	{Attribute: "flow.observation_domain_id", Protocol: "ipfix", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 40, Column: 3}, OutcomeSHA256: "461b701b759a16b2d43d9c7bba16458ad2f03318f49fff0f7f52161278360c06", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.observation_domain_id"},
	{Attribute: "flow.observation_point_id", Protocol: "netflow_v5", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 41, Column: 1}, OutcomeSHA256: "d29ba725344733c61e024f3438ab9692de13b32137500343b25d95f20edaa15b", TestID: "integration/mapping:TestManifestCoverage/netflow_v5/flow.observation_point_id"},
	{Attribute: "flow.observation_point_id", Protocol: "netflow_v9", Classification: []string{"inapplicable"}, MatrixRef: manifestRef{Row: 41, Column: 2}, OutcomeSHA256: "8100f5277db59fc83cb48626c8a90fc292d57a9fb6b378f6319f13c6deec5a0a", TestID: "integration/mapping:TestManifestCoverage/netflow_v9/flow.observation_point_id"},
	{Attribute: "flow.observation_point_id", Protocol: "ipfix", Classification: []string{"lossy"}, MatrixRef: manifestRef{Row: 41, Column: 3}, OutcomeSHA256: "6284c69b45746a666deea4d787bedcec7b8a8b693ec11703b20782d0e20c3c69", TestID: "integration/mapping:TestManifestCoverage/ipfix/flow.observation_point_id"},
}

func TestManifestCoverage(t *testing.T) {
	repoRoot := repositoryRoot(t)
	manifestPath := filepath.Join(repoRoot, "integration", "testdata", "mapping", "manifest.yaml")
	document, raw := readManifest(t, manifestPath)
	if document.Schema != manifestSchema || document.Version != manifestVersion {
		t.Fatalf("manifest identity=%q/%d", document.Schema, document.Version)
	}
	if document.Canonical.Fingerprint != manifestFingerprint {
		t.Fatalf("manifest fingerprint=%q want %q", document.Canonical.Fingerprint, manifestFingerprint)
	}
	if len(manifestRegistry) != 123 {
		t.Fatalf("literal registry has %d cells, want 123", len(manifestRegistry))
	}
	if len(document.Canonical.Cells) != len(manifestRegistry) || len(document.Canonical.Attributes) != 41 || len(document.Canonical.Protocols) != 3 {
		t.Fatalf("manifest dimensions cells=%d attrs=%d protocols=%d", len(document.Canonical.Cells), len(document.Canonical.Attributes), len(document.Canonical.Protocols))
	}
	seen := make(map[string]struct{}, len(manifestRegistry))
	for index, expected := range manifestRegistry {
		key := expected.Protocol + "\x00" + expected.Attribute
		if _, ok := seen[key]; ok {
			t.Fatalf("literal registry duplicate at %d: %s/%s", index, expected.Protocol, expected.Attribute)
		}
		seen[key] = struct{}{}
		actual := document.Canonical.Cells[index]
		if actual.Attribute != expected.Attribute || actual.Protocol != expected.Protocol || !reflect.DeepEqual(actual.Classification, expected.Classification) || actual.MatrixRef != expected.MatrixRef || actual.OutcomeSHA256 != expected.OutcomeSHA256 || actual.TestID != expected.TestID {
			t.Fatalf("registry mismatch at %d: got=%+v want=%+v", index, actual, expected)
		}
		expectedID := "integration/mapping:TestManifestCoverage/" + expected.Protocol + "/" + expected.Attribute
		if expected.TestID != expectedID {
			t.Fatalf("registry test ID=%q want %q", expected.TestID, expectedID)
		}
		t.Run(expected.Protocol+"/"+expected.Attribute, func(t *testing.T) {
			exerciseMappingCell(t, expected)
		})
	}
	if len(seen) != 123 {
		t.Fatalf("literal registry unique cells=%d", len(seen))
	}
	checkManifestMutations(t, repoRoot, raw)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func readManifest(t *testing.T, path string) (manifestDocument, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document manifestDocument
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("manifest has trailing JSON")
	}
	return document, raw
}

func exerciseMappingCell(t *testing.T, cell registryCell) {
	t.Helper()
	if cell.Protocol == "netflow_v9" && (cell.Attribute == "flow.icmp_type" || cell.Attribute == "flow.icmp_code") {
		exerciseV9ICMPComposite(t)
		return
	}
	if cell.Protocol == "netflow_v5" {
		if hasClassification(cell, "exact") || hasClassification(cell, "lossy") || hasClassification(cell, "synthesized") {
			exerciseV5ProfileCell(t, cell)
		} else {
			exerciseV5UnsupportedCell(t, cell)
		}
		exerciseNegativeArms(t, cell)
		return
	}
	if hasClassification(cell, "unsupported") || hasClassification(cell, "inapplicable") {
		if cell.Protocol != "ipfix" || (cell.Attribute != "flow.time_received" && cell.Attribute != "network.type" && cell.Attribute != "flow.src_mac" && cell.Attribute != "flow.dst_mac") {
			code := staticmapping.ErrCodeUnsupported
			if hasClassification(cell, "inapplicable") && !hasClassification(cell, "unsupported") {
				code = staticmapping.ErrCodeInapplicable
			}
			assertCompileRejectsCode(t, explicitConfig(protocolFor(cell.Protocol), cell.Attribute, ""), code)
			return
		}
	}
	exerciseExplicitPositive(t, cell)
	exerciseNegativeArms(t, cell)
}

func hasClassification(cell registryCell, want string) bool {
	for _, classification := range cell.Classification {
		if classification == want {
			return true
		}
	}
	return false
}

func exerciseV5ProfileCell(t *testing.T, cell registryCell) {
	t.Helper()
	compiled, err := staticmapping.Compile(profileConfig(wire.ProtocolV5))
	if err != nil {
		t.Fatalf("v5 profile compile: %v", err)
	}
	shape, ok := compiled.Catalog().ShapeAt(0)
	if !ok || shape.ID() != 1 || shape.Family() != wire.FamilyIPv4 || shape.FieldCount() != 20 || shape.RecordLength() != 48 {
		t.Fatalf("v5 fixed shape=%+v ok=%v", shape, ok)
	}
	record := canonicalRecord(wire.FamilyIPv4, "tcp", "netflow_v5")
	mapped, err := compiled.Map(record, nil)
	if err != nil {
		t.Fatalf("v5 profile map %s: %v", cell.Attribute, err)
	}
	if mapped.Len() != shape.FieldCount() || mapped.Family() != wire.FamilyIPv4 {
		t.Fatalf("v5 mapped %s=%d/%v want %d/ipv4", cell.Attribute, mapped.Len(), mapped.Family(), shape.FieldCount())
	}
	field := fieldForCanonical(t, cell.Attribute)
	if field == wire.FieldFlowSamplingRate {
		if _, index := descriptorForField(shape, field); index >= 0 {
			t.Fatalf("v5 sampling unexpectedly has data descriptor at %d", index)
		}
		assertCompileRejectsCode(t, explicitConfig(wire.ProtocolV5, cell.Attribute, ""), staticmapping.ErrCodeProfile)
		// Sampling is the v5 fixed-profile header slot, not a data descriptor.
		// Exercise several valid values and prove the fixed shape remains intact.
		for _, rate := range []uint64{0, 1000, 16383} {
			withRate := replaceRecordValue(t, record, wire.FieldFlowSamplingRate, wire.UintValue(rate))
			if _, mapErr := compiled.Map(withRate, nil); mapErr != nil {
				t.Fatalf("v5 sampling slot rate=%d: %v", rate, mapErr)
			}
		}
		return
	}
	index := -1
	for i := 0; i < shape.FieldCount(); i++ {
		descriptor, _ := shape.DescriptorAt(i)
		if descriptor.Field == field {
			index = i
			assertDescriptor(t, descriptor, expectedDescriptor(wire.ProtocolV5, field, wire.FamilyIPv4, ""))
			break
		}
	}
	if index < 0 {
		t.Fatalf("v5 fixed profile omitted %s", cell.Attribute)
	}
	want := expectedMappedValue(record, wire.ProtocolV5, field, "", wire.FamilyIPv4)
	got, ok := mapped.ValueAt(index)
	if !ok || got != want {
		t.Fatalf("v5 mapped %s=%+v/%v want %+v/true", cell.Attribute, got, ok, want)
	}
}

func exerciseV5UnsupportedCell(t *testing.T, cell registryCell) {
	t.Helper()
	compiled, err := staticmapping.Compile(profileConfig(wire.ProtocolV5))
	if err != nil {
		t.Fatalf("v5 profile compile: %v", err)
	}
	shape, ok := compiled.Catalog().ShapeAt(0)
	if !ok {
		t.Fatal("v5 fixed shape missing")
	}
	field := fieldForCanonical(t, cell.Attribute)
	if _, index := descriptorForField(shape, field); index >= 0 {
		t.Fatalf("v5 fixed profile unexpectedly contains %s at descriptor %d", cell.Attribute, index)
	}
	record := canonicalRecord(wire.FamilyIPv4, "tcp", "netflow_v5")
	mapped, err := compiled.Map(record, nil)
	if err != nil {
		t.Fatalf("v5 fixed profile map %s: %v", cell.Attribute, err)
	}
	if mapped.Len() != shape.FieldCount() || mapped.Len() != 20 {
		t.Fatalf("v5 fixed profile map %s values=%d want fixed 20", cell.Attribute, mapped.Len())
	}
	assertCompileRejectsCode(t, explicitConfig(wire.ProtocolV5, cell.Attribute, ""), staticmapping.ErrCodeProfile)
}

func exerciseExplicitPositive(t *testing.T, cell registryCell) {
	t.Helper()
	protocol := protocolFor(cell.Protocol)
	target := mappingTarget(cell.Protocol, cell.Attribute)
	config := explicitConfig(protocol, cell.Attribute, target)
	if (cell.Attribute == "flow.start" || cell.Attribute == "flow.end") && protocol == wire.ProtocolV9 {
		config.HasUptimeOrigin = true
		config.UptimeOriginUnixNanos = 1788220800000000000
	}
	compiled, err := staticmapping.Compile(config)
	if err != nil {
		t.Fatalf("compile %s/%s target=%q: %v", cell.Protocol, cell.Attribute, target, err)
	}
	field := fieldForCanonical(t, cell.Attribute)
	if compiled.ShapeCount() == 0 || compiled.ShapeCount() > 2 {
		t.Fatalf("%s/%s shape count=%d", cell.Protocol, cell.Attribute, compiled.ShapeCount())
	}
	for shapeIndex := 0; shapeIndex < compiled.ShapeCount(); shapeIndex++ {
		shape, ok := compiled.Catalog().ShapeAt(shapeIndex)
		if !ok {
			t.Fatalf("%s/%s missing shape %d", cell.Protocol, cell.Attribute, shapeIndex)
		}
		family := shape.Family()
		transport := "tcp"
		if field == wire.FieldFlowICMPType || field == wire.FieldFlowICMPCode {
			transport = "icmp"
			if family == wire.FamilyIPv6 {
				transport = "ipv6-icmp"
			}
		}
		flowType := cell.Protocol
		record := canonicalRecord(family, transport, flowType)
		if field == wire.FieldFlowIPFlags {
			flags := uint64(3)
			if family == wire.FamilyIPv6 {
				flags = 1
			}
			record = replaceRecordValue(t, record, field, wire.UintValue(flags))
		}
		mapped, mapErr := compiled.Map(record, nil)
		if mapErr != nil {
			t.Fatalf("map %s/%s shape=%d: %v", cell.Protocol, cell.Attribute, shapeIndex, mapErr)
		}
		if mapped.Len() != 1 {
			t.Fatalf("map %s/%s values=%d want 1", cell.Protocol, cell.Attribute, mapped.Len())
		}
		descriptor, descriptorIndex := descriptorForField(shape, field)
		if descriptorIndex < 0 {
			t.Fatalf("shape %d omitted selected descriptor %s", shapeIndex, cell.Attribute)
		}
		assertDescriptor(t, descriptor, expectedDescriptor(protocol, field, family, target))
		got, ok := mapped.ValueAt(0)
		want := expectedMappedValue(record, protocol, field, target, family)
		if !ok || got != want {
			t.Fatalf("map %s/%s value=%+v/%v want %+v/true", cell.Protocol, cell.Attribute, got, ok, want)
		}
	}
	if protocol == wire.ProtocolIPFIX && (field == wire.FieldFlowSrcMAC || field == wire.FieldFlowDstMAC) {
		exerciseIPFIXMACTargets(t, field)
	}
}

func exerciseNegativeArms(t *testing.T, cell registryCell) {
	t.Helper()
	protocol := protocolFor(cell.Protocol)
	switch {
	case cell.Protocol == "netflow_v5" && cell.Attribute == "flow.io.bytes":
		for _, guarantee := range []string{"", "l2_total_octets"} {
			config := profileConfig(wire.ProtocolV5)
			config.InputGuarantees.FlowIOBytes = guarantee
			assertCompileRejectsCodePath(t, config, staticmapping.ErrCodeProvenance, "mapping.input_guarantees.flow_io_bytes")
		}
	case cell.Protocol == "netflow_v5" && (cell.Attribute == "flow.start" || cell.Attribute == "flow.end"):
		config := profileConfig(wire.ProtocolV5)
		config.HasUptimeOrigin = false
		assertCompileRejectsCodePath(t, config, staticmapping.ErrCodeProvenance, "mapping.uptime_origin")
		exerciseV5TimeCell(t, fieldForCanonical(t, cell.Attribute))
	case cell.Protocol == "netflow_v9" && (cell.Attribute == "flow.start" || cell.Attribute == "flow.end"):
		config := explicitConfig(protocol, cell.Attribute, "")
		config.HasUptimeOrigin = false
		assertCompileRejectsCode(t, config, staticmapping.ErrCodeProvenance)
	case cell.Protocol == "netflow_v9" && cell.Attribute == "flow.vlan_id":
		config := explicitConfig(protocol, cell.Attribute, "")
		config.LossPolicy = staticmapping.LossPolicyReject
		assertCompileRejectsCode(t, config, staticmapping.ErrCodePolicy)
	case cell.Protocol == "ipfix" && cell.Attribute == "network.type":
		assertCompileRejectsCode(t, explicitConfig(protocol, cell.Attribute, ""), staticmapping.ErrCodeSelector)
		config := explicitConfig(protocol, cell.Attribute, "ip_version")
		compiled, err := staticmapping.Compile(config)
		if err != nil {
			t.Fatalf("ipfix network-type opt-in compile: %v", err)
		}
		bad := replaceRecordValue(t, canonicalRecord(wire.FamilyIPv4, "tcp", "ipfix"), wire.FieldNetworkType, wire.StringValue("ipv6"))
		_, mapErr := compiled.Map(bad, nil)
		assertRuntimeReason(t, mapErr, staticmapping.RuntimeFamilyMismatch)
	case cell.Protocol == "ipfix" && (cell.Attribute == "flow.time_received" || cell.Attribute == "flow.src_mac" || cell.Attribute == "flow.dst_mac"):
		assertCompileRejectsCode(t, explicitConfig(protocol, cell.Attribute, ""), staticmapping.ErrCodeSelector)
	case cell.Protocol == "ipfix" && cell.Attribute == "flow.ip_flags":
		config := explicitConfig(protocol, cell.Attribute, "")
		compiled, err := staticmapping.Compile(config)
		if err != nil {
			t.Fatalf("ipfix IP-flags opt-in compile: %v", err)
		}
		_, mapErr := compiled.Map(canonicalRecord(wire.FamilyIPv4, "tcp", "netflow_v9"), nil)
		assertRuntimeReason(t, mapErr, staticmapping.RuntimeProtocolMismatch)
	case cell.Protocol == "netflow_v9" && (cell.Attribute == "flow.icmp_type" || cell.Attribute == "flow.icmp_code"):
		// The composite helper owns all protocol/family/missing-value negatives.
	default:
		// Unsupported and inapplicable cells are checked above with their
		// exact compiler code. Positive cells have no additional negative arm.
	}
}

func exerciseV5TimeCell(t *testing.T, field wire.CanonicalField) {
	t.Helper()
	config := profileConfig(wire.ProtocolV5)
	compiled, err := staticmapping.Compile(config)
	if err != nil {
		t.Fatalf("v5 time profile compile: %v", err)
	}
	shape, ok := compiled.Catalog().ShapeAt(0)
	if !ok {
		t.Fatal("v5 fixed shape missing")
	}
	descriptor, ordinal := descriptorForField(shape, field)
	if ordinal < 0 {
		t.Fatalf("v5 time descriptor omitted %s", field.CanonicalName())
	}
	wantOrdinal := 7
	if field == wire.FieldFlowEnd {
		wantOrdinal = 8
	}
	if ordinal != wantOrdinal {
		t.Fatalf("v5 time descriptor %s ordinal=%d want %d", field.CanonicalName(), ordinal, wantOrdinal)
	}
	assertDescriptor(t, descriptor, expectedDescriptor(wire.ProtocolV5, field, wire.FamilyIPv4, ""))
	base := canonicalRecord(wire.FamilyIPv4, "tcp", "netflow_v5")
	origin := config.UptimeOriginUnixNanos
	invalidTimes := []struct {
		name  string
		value uint64
	}{
		{name: "pre-origin", value: origin - 1},
		{name: "sub-millisecond", value: origin + 1},
		{name: "elapsed-overflow", value: origin + (uint64(math.MaxUint32)+1)*1_000_000},
	}
	for _, tc := range invalidTimes {
		t.Run(tc.name, func(t *testing.T) {
			record := replaceRecordValue(t, base, field, wire.UnixNanosValue(tc.value))
			_, mapErr := compiled.Map(record, nil)
			assertRuntimeReasonOrdinal(t, mapErr, staticmapping.RuntimeTimeInvalid, ordinal)
		})
	}
	ordering := base
	if field == wire.FieldFlowStart {
		ordering = replaceRecordValue(t, base, wire.FieldFlowStart, wire.UnixNanosValue(origin+1_002_000_000))
	} else {
		ordering = replaceRecordValue(t, base, wire.FieldFlowEnd, wire.UnixNanosValue(origin+999_000_000))
	}
	_, err = compiled.Map(ordering, nil)
	assertRuntimeReasonOrdinal(t, err, staticmapping.RuntimeTimeInvalid, 0)
}

func exerciseIPFIXMACTargets(t *testing.T, field wire.CanonicalField) {
	t.Helper()
	targets := []struct {
		name string
		id   uint16
	}{
		{"source_mac_address", 56},
		{"post_source_mac_address", 81},
	}
	if field == wire.FieldFlowDstMAC {
		targets = []struct {
			name string
			id   uint16
		}{
			{"destination_mac_address", 80},
			{"post_destination_mac_address", 57},
		}
	}
	for _, target := range targets {
		config := explicitConfig(wire.ProtocolIPFIX, field.CanonicalName(), target.name)
		compiled, err := staticmapping.Compile(config)
		if err != nil {
			t.Fatalf("IPFIX MAC target %q compile: %v", target.name, err)
		}
		shape, ok := compiled.Catalog().ShapeAt(0)
		if !ok {
			t.Fatalf("IPFIX MAC target %q shape missing", target.name)
		}
		descriptor, index := descriptorForField(shape, field)
		if index < 0 || descriptor.ID != target.id || descriptor.Length != 6 || descriptor.Encoding != wire.EncodingMACAddress {
			t.Fatalf("IPFIX MAC target=%q descriptor=%+v index=%d", target.name, descriptor, index)
		}
		mapped, err := compiled.Map(canonicalRecord(wire.FamilyIPv4, "tcp", "ipfix"), nil)
		if err != nil {
			t.Fatalf("IPFIX MAC target %q map: %v", target.name, err)
		}
		want, _ := canonicalRecord(wire.FamilyIPv4, "tcp", "ipfix").Lookup(field)
		got, ok := mapped.ValueAt(0)
		if !ok || got != want {
			t.Fatalf("IPFIX MAC target=%q value=%+v/%v want %+v/true", target.name, got, ok, want)
		}
	}
}

func exerciseV9ICMPComposite(t *testing.T) {
	t.Helper()
	config := explicitConfig(wire.ProtocolV9, "flow.icmp_type_code", "")
	compiled, err := staticmapping.Compile(config)
	if err != nil {
		t.Fatalf("v9 ICMP composite compile: %v", err)
	}
	shape, ok := compiled.Catalog().ShapeAt(0)
	if !ok || compiled.ShapeCount() != 1 || shape.Family() != wire.FamilyIPv4 {
		t.Fatalf("v9 ICMP composite shapes=%d shape=%+v/%v", compiled.ShapeCount(), shape, ok)
	}
	descriptor, index := descriptorForField(shape, wire.FieldFlowICMPTypeCode)
	if index < 0 {
		t.Fatal("v9 ICMP composite descriptor omitted")
	}
	assertDescriptor(t, descriptor, expectedDescriptor(wire.ProtocolV9, wire.FieldFlowICMPTypeCode, wire.FamilyIPv4, ""))
	good := canonicalRecord(wire.FamilyIPv4, "icmp", "netflow_v9")
	good = replaceRecordValue(t, good, wire.FieldFlowICMPCode, wire.UintValue(3))
	mapped, err := compiled.Map(good, nil)
	if err != nil {
		t.Fatalf("v9 ICMP composite map: %v", err)
	}
	value, ok := mapped.ValueAt(0)
	if !ok || value != wire.UintValue(8<<8|3) {
		t.Fatalf("v9 ICMP composite encoded=%+v/%v want 2051/true", value, ok)
	}
	_, err = compiled.Map(canonicalRecord(wire.FamilyIPv4, "tcp", "netflow_v9"), nil)
	assertRuntimeReason(t, err, staticmapping.RuntimeProtocolMismatch)
	_, err = compiled.Map(canonicalRecord(wire.FamilyIPv6, "ipv6-icmp", "netflow_v9"), nil)
	assertRuntimeReason(t, err, staticmapping.RuntimeFamilyMismatch)
	missingType := withoutRecordValue(t, good, wire.FieldFlowICMPType)
	_, err = compiled.Map(missingType, nil)
	assertRuntimeReason(t, err, staticmapping.RuntimeMissingField)
	missingCode := withoutRecordValue(t, good, wire.FieldFlowICMPCode)
	_, err = compiled.Map(missingCode, nil)
	assertRuntimeReason(t, err, staticmapping.RuntimeMissingField)
}

func assertCompileRejectsCode(t *testing.T, config staticmapping.Config, want staticmapping.ErrorCode) {
	t.Helper()
	_, err := staticmapping.Compile(config)
	if err == nil {
		t.Fatalf("compile unexpectedly accepted; want code=%d", want)
	}
	var configErr *staticmapping.ConfigError
	if !errors.As(err, &configErr) || configErr.Code != want {
		t.Fatalf("compile error=%T %v want code=%d", err, err, want)
	}
}

func assertCompileRejectsCodePath(t *testing.T, config staticmapping.Config, want staticmapping.ErrorCode, path string) {
	t.Helper()
	_, err := staticmapping.Compile(config)
	if err == nil {
		t.Fatalf("compile unexpectedly accepted; want code=%d path=%s", want, path)
	}
	var configErr *staticmapping.ConfigError
	if !errors.As(err, &configErr) || configErr.Code != want || configErr.Path != path {
		t.Fatalf("compile error=%T %v want code=%d path=%s", err, err, want, path)
	}
}

func assertRuntimeReason(t *testing.T, err error, want staticmapping.RuntimeReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("runtime mapping unexpectedly accepted; want reason=%d", want)
	}
	var runtimeErr *staticmapping.RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != want {
		t.Fatalf("runtime error=%T %v want reason=%d", err, err, want)
	}
}

func assertRuntimeReasonOrdinal(t *testing.T, err error, want staticmapping.RuntimeReason, ordinal int) {
	t.Helper()
	if err == nil {
		t.Fatalf("runtime mapping unexpectedly accepted; want reason=%d ordinal=%d", want, ordinal)
	}
	var runtimeErr *staticmapping.RuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Reason != want || int(runtimeErr.Ordinal) != ordinal {
		t.Fatalf("runtime error=%T %v want reason=%d ordinal=%d", err, err, want, ordinal)
	}
}

func descriptorForField(shape wire.Shape, field wire.CanonicalField) (wire.FieldDescriptor, int) {
	for index := 0; index < shape.FieldCount(); index++ {
		descriptor, _ := shape.DescriptorAt(index)
		if descriptor.Field == field {
			return descriptor, index
		}
	}
	return wire.FieldDescriptor{}, -1
}

func assertDescriptor(t *testing.T, got, want wire.FieldDescriptor) {
	t.Helper()
	if got != want {
		t.Fatalf("descriptor=%+v want=%+v", got, want)
	}
}

func expectedDescriptor(protocol wire.Protocol, field wire.CanonicalField, family wire.Family, target string) wire.FieldDescriptor {
	descriptor := wire.FieldDescriptor{Protocol: protocol, Field: field, Encoding: wire.EncodingUnspecified}
	v4 := family == wire.FamilyIPv4
	if protocol == wire.ProtocolV5 {
		switch field {
		case wire.FieldSourceAddress:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 1, 4, wire.EncodingIPv4Address
		case wire.FieldDestinationAddress:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 2, 4, wire.EncodingIPv4Address
		case wire.FieldFlowNextHop:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 3, 4, wire.EncodingIPv4Address
		case wire.FieldFlowInIf:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 4, 2, wire.EncodingUnsigned16
		case wire.FieldFlowOutIf:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 5, 2, wire.EncodingUnsigned16
		case wire.FieldFlowIOPackets:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 6, 4, wire.EncodingUnsigned32
		case wire.FieldFlowIOBytes:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 7, 4, wire.EncodingUnsigned32
		case wire.FieldFlowStart:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 8, 4, wire.EncodingUnsigned32
		case wire.FieldFlowEnd:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 9, 4, wire.EncodingUnsigned32
		case wire.FieldSourcePort:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 10, 2, wire.EncodingUnsigned16
		case wire.FieldDestinationPort:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 11, 2, wire.EncodingUnsigned16
		case wire.FieldFlowTCPFlags:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 13, 1, wire.EncodingUnsigned8
		case wire.FieldNetworkTransport:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 14, 1, wire.EncodingUnsigned8
		case wire.FieldFlowIPTOS:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 15, 1, wire.EncodingUnsigned8
		case wire.FieldFlowSrcAS:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 16, 2, wire.EncodingUnsigned16
		case wire.FieldFlowDstAS:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 17, 2, wire.EncodingUnsigned16
		case wire.FieldFlowSrcNet:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 18, 1, wire.EncodingUnsigned8
		case wire.FieldFlowDstNet:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 19, 1, wire.EncodingUnsigned8
		}
		return descriptor
	}
	if protocol == wire.ProtocolV9 {
		switch field {
		case wire.FieldSourceAddress:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 8, 27), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
		case wire.FieldDestinationAddress:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 12, 28), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
		case wire.FieldFlowNextHop:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 15, 62), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
		case wire.FieldFlowBGPNextHop:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 18, 63), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
		case wire.FieldFlowSrcNet:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 9, 29), 1, wire.EncodingUnsigned8
		case wire.FieldFlowDstNet:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 13, 30), 1, wire.EncodingUnsigned8
		case wire.FieldFlowIOBytes:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(target == "out_bytes", 23, 1), 4, wire.EncodingUnsigned32
		case wire.FieldFlowIOPackets:
			descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(target == "out_packets", 24, 2), 4, wire.EncodingUnsigned32
		case wire.FieldNetworkTransport:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 4, 1, wire.EncodingUnsigned8
		case wire.FieldFlowIPTOS:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 5, 1, wire.EncodingUnsigned8
		case wire.FieldFlowTCPFlags:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 6, 1, wire.EncodingUnsigned8
		case wire.FieldSourcePort:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 7, 2, wire.EncodingUnsigned16
		case wire.FieldFlowInIf:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 10, 2, wire.EncodingUnsigned16
		case wire.FieldDestinationPort:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 11, 2, wire.EncodingUnsigned16
		case wire.FieldFlowOutIf:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 14, 2, wire.EncodingUnsigned16
		case wire.FieldFlowSrcAS:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 16, 4, wire.EncodingUnsigned32
		case wire.FieldFlowDstAS:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 17, 4, wire.EncodingUnsigned32
		case wire.FieldFlowEnd:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 21, 4, wire.EncodingUnsigned32
		case wire.FieldFlowStart:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 22, 4, wire.EncodingUnsigned32
		case wire.FieldFlowSamplingRate:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 34, 4, wire.EncodingUnsigned32
		case wire.FieldFlowIPTTL:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 52, 1, wire.EncodingUnsigned8
		case wire.FieldFlowFragmentID:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 54, 4, wire.EncodingUnsigned32
		case wire.FieldFlowSrcMAC:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 56, 6, wire.EncodingMACAddress
		case wire.FieldFlowDstMAC:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 57, 6, wire.EncodingMACAddress
		case wire.FieldFlowSrcVLAN, wire.FieldFlowVLANID:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 58, 2, wire.EncodingUnsigned16
		case wire.FieldFlowDstVLAN:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 59, 2, wire.EncodingUnsigned16
		case wire.FieldNetworkType:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 60, 1, wire.EncodingUnsigned8
		case wire.FieldFlowFragmentOffset:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 88, 2, wire.EncodingUnsigned16
		case wire.FieldFlowForwardingStatus:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 89, 1, wire.EncodingUnsigned8
		case wire.FieldFlowIPv6FlowLabel:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 31, 3, wire.EncodingOctetArray
		case wire.FieldFlowICMPTypeCode:
			descriptor.ID, descriptor.Length, descriptor.Encoding = 32, 2, wire.EncodingUnsigned16
		}
		return descriptor
	}
	switch field {
	case wire.FieldFlowIOBytes:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(target == "post_octet_delta_count", 23, 1), 8, wire.EncodingUnsigned64
	case wire.FieldFlowIOPackets:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(target == "post_packet_delta_count", 24, 2), 8, wire.EncodingUnsigned64
	case wire.FieldNetworkTransport:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 4, 1, wire.EncodingUnsigned8
	case wire.FieldNetworkType:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 60, 1, wire.EncodingUnsigned8
	case wire.FieldFlowTimeReceived:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 325, 8, wire.EncodingDateTimeNanoseconds
	case wire.FieldFlowStart:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 156, 8, wire.EncodingDateTimeNanoseconds
	case wire.FieldFlowEnd:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 157, 8, wire.EncodingDateTimeNanoseconds
	case wire.FieldFlowIPFlags:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 197, 1, wire.EncodingUnsigned8
	case wire.FieldFlowSrcMAC:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(target == "post_source_mac_address", 81, 56), 6, wire.EncodingMACAddress
	case wire.FieldFlowDstMAC:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(target == "destination_mac_address", 80, 57), 6, wire.EncodingMACAddress
	case wire.FieldSourceAddress:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 8, 27), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
	case wire.FieldDestinationAddress:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 12, 28), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
	case wire.FieldFlowNextHop:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 15, 62), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
	case wire.FieldFlowBGPNextHop:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 18, 63), choose16(v4, 4, 16), chooseEncoding(v4, wire.EncodingIPv4Address, wire.EncodingIPv6Address)
	case wire.FieldFlowSrcNet:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 9, 29), 1, wire.EncodingUnsigned8
	case wire.FieldFlowDstNet:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 13, 30), 1, wire.EncodingUnsigned8
	case wire.FieldSourcePort:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 7, 2, wire.EncodingUnsigned16
	case wire.FieldDestinationPort:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 11, 2, wire.EncodingUnsigned16
	case wire.FieldFlowIPTOS:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 5, 1, wire.EncodingUnsigned8
	case wire.FieldFlowTCPFlags:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 6, 2, wire.EncodingUnsigned16
	case wire.FieldFlowInIf:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 10, 4, wire.EncodingUnsigned32
	case wire.FieldFlowOutIf:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 14, 4, wire.EncodingUnsigned32
	case wire.FieldFlowSrcAS:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 16, 4, wire.EncodingUnsigned32
	case wire.FieldFlowDstAS:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 17, 4, wire.EncodingUnsigned32
	case wire.FieldFlowSamplingRate:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 34, 4, wire.EncodingUnsigned32
	case wire.FieldFlowIPTTL:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 52, 1, wire.EncodingUnsigned8
	case wire.FieldFlowFragmentID:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 54, 4, wire.EncodingUnsigned32
	case wire.FieldFlowIPv6FlowLabel:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 31, 4, wire.EncodingUnsigned32
	case wire.FieldFlowICMPType:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 176, 178), 1, wire.EncodingUnsigned8
	case wire.FieldFlowICMPCode:
		descriptor.ID, descriptor.Length, descriptor.Encoding = choose16(v4, 177, 179), 1, wire.EncodingUnsigned8
	case wire.FieldFlowSrcVLAN, wire.FieldFlowVLANID:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 58, 2, wire.EncodingUnsigned16
	case wire.FieldFlowDstVLAN:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 59, 2, wire.EncodingUnsigned16
	case wire.FieldFlowFragmentOffset:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 88, 2, wire.EncodingUnsigned16
	case wire.FieldFlowForwardingStatus:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 89, 1, wire.EncodingUnsigned8
	case wire.FieldFlowObservationPointID:
		descriptor.ID, descriptor.Length, descriptor.Encoding = 138, 8, wire.EncodingUnsigned64
	}
	return descriptor
}

func choose16(first bool, yes, no uint16) uint16 {
	if first {
		return yes
	}
	return no
}

func chooseEncoding(first bool, yes, no wire.DescriptorEncoding) wire.DescriptorEncoding {
	if first {
		return yes
	}
	return no
}

func fieldForCanonical(t *testing.T, name string) wire.CanonicalField {
	t.Helper()
	for field := wire.CanonicalField(0); int(field) < wire.CanonicalFieldCount; field++ {
		if field.CanonicalName() == name {
			return field
		}
	}
	t.Fatalf("unknown canonical field %q", name)
	return wire.FieldInvalid
}

func expectedMappedValue(record wire.NormalizedRecord, protocol wire.Protocol, field wire.CanonicalField, target string, family wire.Family) wire.Value {
	if field == wire.FieldFlowICMPTypeCode {
		return wire.UintValue(8<<8 | 3)
	}
	if field == wire.FieldNetworkTransport {
		value, _ := record.Lookup(field)
		switch value.Text() {
		case "icmp":
			return wire.UintValue(1)
		case "tcp":
			return wire.UintValue(6)
		case "ipv6-icmp":
			return wire.UintValue(58)
		default:
			panic(fmt.Sprintf("unexpected protocol token %q in literal expectation", value.Text()))
		}
	}
	if field == wire.FieldNetworkType {
		value, _ := record.Lookup(field)
		switch value.Text() {
		case "ipv4":
			return wire.UintValue(4)
		case "ipv6":
			return wire.UintValue(6)
		default:
			panic(fmt.Sprintf("unexpected network token %q in literal expectation", value.Text()))
		}
	}
	if field == wire.FieldFlowIPFlags {
		if family == wire.FamilyIPv6 {
			return wire.UintValue(0x20)
		}
		return wire.UintValue(0x60)
	}
	if field == wire.FieldFlowIPv6FlowLabel && protocol == wire.ProtocolV9 {
		return wire.BytesValue([]byte{0x01, 0x23, 0x45})
	}
	value, _ := record.Lookup(field)
	return value
}

func replaceRecordValue(t *testing.T, record wire.NormalizedRecord, field wire.CanonicalField, replacement wire.Value) wire.NormalizedRecord {
	t.Helper()
	values := record.Values()
	for index := range values {
		if values[index].Field == field {
			values[index].Value = replacement
			updated, err := wire.NewRecord(record.Family(), values)
			if err != nil {
				t.Fatalf("replace %s: %v", field.CanonicalName(), err)
			}
			return updated
		}
	}
	t.Fatalf("record missing %s", field.CanonicalName())
	return record
}

func withoutRecordValue(t *testing.T, record wire.NormalizedRecord, field wire.CanonicalField) wire.NormalizedRecord {
	t.Helper()
	values := record.Values()
	filtered := values[:0]
	for _, value := range values {
		if value.Field != field {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == len(values) {
		t.Fatalf("record missing %s", field.CanonicalName())
	}
	updated, err := wire.NewRecord(record.Family(), filtered)
	if err != nil {
		t.Fatalf("remove %s: %v", field.CanonicalName(), err)
	}
	return updated
}

func assertCompileRejects(t *testing.T, config staticmapping.Config) {
	t.Helper()
	if _, err := staticmapping.Compile(config); err == nil {
		t.Fatal("unsupported/inapplicable mapping unexpectedly compiled")
	}
}

func profileConfig(protocol wire.Protocol) staticmapping.Config {
	config := staticmapping.Config{Protocol: protocol, LossPolicy: staticmapping.LossPolicyEncodeAndCount, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000, ProtocolIdentifiers: []staticmapping.ProtocolIdentifier{{Token: "tcp", Number: 6}, {Token: "icmp", Number: 1}, {Token: "ipv6-icmp", Number: 58}}}
	if protocol == wire.ProtocolV5 {
		config.Profile = staticmapping.ProfileV5
		config.InputGuarantees = staticmapping.InputGuarantees{FlowIOBytes: "layer3_total_octets"}
	} else if protocol == wire.ProtocolV9 {
		config.Profile = staticmapping.ProfileV9
		config.NetworkTypeVersions = []staticmapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	} else {
		config.Profile = staticmapping.ProfileIPFIX
		config.NetworkTypeVersions = []staticmapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	}
	return config
}

func explicitConfig(protocol wire.Protocol, attribute, target string) staticmapping.Config {
	config := staticmapping.Config{Protocol: protocol, LossPolicy: staticmapping.LossPolicyEncodeAndCount, HasUptimeOrigin: true, UptimeOriginUnixNanos: 1788220800000000000, Fields: []staticmapping.FieldSelection{{Canonical: attribute, Target: target}}}
	if attribute == "network.transport" || attribute == "flow.icmp_type_code" || attribute == "flow.icmp_type" || attribute == "flow.icmp_code" {
		config.ProtocolIdentifiers = []staticmapping.ProtocolIdentifier{{Token: "tcp", Number: 6}, {Token: "icmp", Number: 1}, {Token: "ipv6-icmp", Number: 58}}
	}
	if attribute == "network.type" {
		config.NetworkTypeVersions = []staticmapping.NetworkTypeVersion{{Token: "ipv4", Version: 4}, {Token: "ipv6", Version: 6}}
	}
	return config
}

func mappingTarget(protocol, attribute string) string {
	if protocol == "netflow_v9" {
		switch attribute {
		case "flow.io.bytes":
			return "in_bytes"
		case "flow.io.packets":
			return "in_packets"
		}
	}
	if protocol == "ipfix" {
		switch attribute {
		case "flow.io.bytes":
			return "octet_delta_count"
		case "flow.io.packets":
			return "packet_delta_count"
		case "network.type":
			return "ip_version"
		case "flow.time_received":
			return "observation_time_nanoseconds"
		case "flow.src_mac":
			return "source_mac_address"
		case "flow.dst_mac":
			return "destination_mac_address"
		}
	}
	return ""
}

func protocolFor(protocol string) wire.Protocol {
	switch protocol {
	case "netflow_v5":
		return wire.ProtocolV5
	case "netflow_v9":
		return wire.ProtocolV9
	case "ipfix":
		return wire.ProtocolIPFIX
	default:
		panic("unknown protocol " + protocol)
	}
}

func canonicalRecord(family wire.Family, transport, flowType string) wire.NormalizedRecord {
	var source, destination, nextHop, bgpNextHop wire.Value
	if family == wire.FamilyIPv6 {
		source = wire.IPValue(netip.MustParseAddr("2001:db8::1"))
		destination = wire.IPValue(netip.MustParseAddr("2001:db8::2"))
		nextHop = wire.IPValue(netip.MustParseAddr("2001:db8::fe"))
		bgpNextHop = wire.IPValue(netip.MustParseAddr("2001:db8::3"))
	} else {
		source = wire.IPValue(netip.MustParseAddr("192.0.2.1"))
		destination = wire.IPValue(netip.MustParseAddr("198.51.100.2"))
		nextHop = wire.IPValue(netip.MustParseAddr("192.0.2.254"))
		bgpNextHop = wire.IPValue(netip.MustParseAddr("198.51.100.1"))
	}
	flowLabel := uint64(0)
	srcNet, dstNet := uint64(24), uint64(24)
	networkType := "ipv4"
	if family == wire.FamilyIPv6 {
		flowLabel, srcNet, dstNet, networkType = 74565, 64, 64, "ipv6"
	}
	macSource, _ := wire.ParseMACValue("00:11:22:33:44:55")
	macDestination, _ := wire.ParseMACValue("66:77:88:99:aa:bb")
	values := []wire.FieldValue{
		{Field: wire.FieldSourceAddress, Value: source}, {Field: wire.FieldSourcePort, Value: wire.UintValue(12345)},
		{Field: wire.FieldDestinationAddress, Value: destination}, {Field: wire.FieldDestinationPort, Value: wire.UintValue(443)},
		{Field: wire.FieldNetworkTransport, Value: wire.StringValue(transport)}, {Field: wire.FieldNetworkType, Value: wire.StringValue(networkType)},
		{Field: wire.FieldFlowIOBytes, Value: wire.UintValue(56789)}, {Field: wire.FieldFlowIOPackets, Value: wire.UintValue(1234)},
		{Field: wire.FieldFlowType, Value: wire.StringValue(flowType)}, {Field: wire.FieldFlowSequenceNum, Value: wire.UintValue(7)},
		{Field: wire.FieldFlowTimeReceived, Value: wire.UnixNanosValue(1788220802000000000)}, {Field: wire.FieldFlowStart, Value: wire.UnixNanosValue(1788220801000000000)},
		{Field: wire.FieldFlowEnd, Value: wire.UnixNanosValue(1788220801001000000)}, {Field: wire.FieldFlowSamplingRate, Value: wire.UintValue(1000)},
		{Field: wire.FieldFlowSamplerAddress, Value: source}, {Field: wire.FieldFlowTCPFlags, Value: wire.UintValue(24)},
		{Field: wire.FieldFlowInIf, Value: wire.UintValue(10)}, {Field: wire.FieldFlowOutIf, Value: wire.UintValue(20)},
		{Field: wire.FieldFlowIPTOS, Value: wire.UintValue(0)}, {Field: wire.FieldFlowIPTTL, Value: wire.UintValue(64)},
		{Field: wire.FieldFlowIPFlags, Value: wire.UintValue(0)}, {Field: wire.FieldFlowFragmentID, Value: wire.UintValue(0)},
		{Field: wire.FieldFlowFragmentOffset, Value: wire.UintValue(0)}, {Field: wire.FieldFlowIPv6FlowLabel, Value: wire.UintValue(flowLabel)},
		{Field: wire.FieldFlowICMPType, Value: wire.UintValue(8)}, {Field: wire.FieldFlowICMPCode, Value: wire.UintValue(0)},
		{Field: wire.FieldFlowSrcMAC, Value: macSource}, {Field: wire.FieldFlowDstMAC, Value: macDestination},
		{Field: wire.FieldFlowSrcVLAN, Value: wire.UintValue(100)}, {Field: wire.FieldFlowDstVLAN, Value: wire.UintValue(200)},
		{Field: wire.FieldFlowVLANID, Value: wire.UintValue(100)}, {Field: wire.FieldFlowNextHop, Value: nextHop},
		{Field: wire.FieldFlowNextHopAS, Value: wire.UintValue(64512)}, {Field: wire.FieldFlowSrcAS, Value: wire.UintValue(64513)},
		{Field: wire.FieldFlowDstAS, Value: wire.UintValue(64514)}, {Field: wire.FieldFlowBGPNextHop, Value: bgpNextHop},
		{Field: wire.FieldFlowSrcNet, Value: wire.UintValue(srcNet)}, {Field: wire.FieldFlowDstNet, Value: wire.UintValue(dstNet)},
		{Field: wire.FieldFlowForwardingStatus, Value: wire.UintValue(0)}, {Field: wire.FieldFlowObservationDomainID, Value: wire.UintValue(42)},
		{Field: wire.FieldFlowObservationPointID, Value: wire.UintValue(7)},
	}
	record, err := wire.NewRecord(family, values)
	if err != nil {
		panic(fmt.Sprintf("canonical record: %v", err))
	}
	return record
}

func checkManifestMutations(t *testing.T, repoRoot string, raw []byte) {
	t.Helper()
	t.Run("valid-manifest", func(t *testing.T) {
		if err := runCheckerBytes(t, repoRoot, raw); err != nil {
			t.Fatalf("valid manifest rejected: %v", err)
		}
	})
	var base map[string]any
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing-cell", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"] = doc["canonical"].(map[string]any)["cells"].([]any)[1:]
		}},
		{"duplicate-cell", func(doc map[string]any) {
			c := doc["canonical"].(map[string]any)["cells"].([]any)
			doc["canonical"].(map[string]any)["cells"] = append(c, c[0])
		}},
		{"reordered-cell", func(doc map[string]any) {
			c := doc["canonical"].(map[string]any)["cells"].([]any)
			c[0], c[1] = c[1], c[0]
		}},
		{"stale-cell", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["attribute"] = "flow.stale"
		}},
		{"source-drift", func(doc map[string]any) {
			doc["sources"].(map[string]any)["matrix"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		}},
		{"qualified-outcome-drift", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["outcome"] = "**exact** hostile-canary"
		}},
		{"outcome-digest-drift", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["outcome_sha256"] = strings.Repeat("0", 64)
		}},
		{"matrix-reference-drift", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["matrix_ref"].(map[string]any)["row"] = 2
		}},
		{"nested-unknown-key", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["matrix_ref"].(map[string]any)["nested"] = true
		}},
		{"nested-missing-key", func(doc map[string]any) {
			delete(doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["matrix_ref"].(map[string]any), "column")
		}},
		{"reclassified-cell", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["classification"] = []any{"lossy"}
		}},
		{"malformed-classification-member", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["classification"] = []any{"exact", "not-a-class"}
		}},
		{"malformed-classification-order", func(doc map[string]any) {
			for _, rawCell := range doc["canonical"].(map[string]any)["cells"].([]any) {
				cell := rawCell.(map[string]any)
				classes := cell["classification"].([]any)
				if len(classes) > 1 {
					classes[0], classes[1] = classes[1], classes[0]
					return
				}
			}
		}},
		{"untested-cell", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["test_id"] = "internal/mapping:TestCustom"
		}},
		{"stale-test-id", func(doc map[string]any) {
			doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["test_id"] = "integration/mapping:TestManifestCoverage/netflow_v5/stale"
		}},
		{"canonical-as-extra", func(doc map[string]any) {
			doc["extras"].(map[string]any)["v9_private"].(map[string]any)["test_id"] = manifestRegistry[0].TestID
		}},
		{"unknown-key", func(doc map[string]any) { doc["unexpected"] = true }},
		{"malformed-type", func(doc map[string]any) { doc["version"] = "1" }},
		{"extra-contamination", func(doc map[string]any) {
			doc["extras"].(map[string]any)["flow.io.bytes/netflow_v5"] = map[string]any{"test_id": "internal/mapping:TestCustom"}
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			doc := cloneJSONMap(t, base)
			mutation.mutate(doc)
			first := runCheckerMutation(t, repoRoot, doc)
			second := runCheckerMutation(t, repoRoot, doc)
			if first == nil || second == nil {
				t.Fatal("invalid mutation accepted")
			}
			if first.Error() != second.Error() {
				t.Fatalf("mutation result is nondeterministic: %v / %v", first, second)
			}
		})
	}
	duplicateJSON := strings.Replace(string(raw), `"schema": "`+manifestSchema+`"`, `"schema": "`+manifestSchema+`", "schema": "`+manifestSchema+`"`, 1)
	t.Run("duplicate-json-key", func(t *testing.T) {
		first := runCheckerBytes(t, repoRoot, []byte(duplicateJSON))
		second := runCheckerBytes(t, repoRoot, []byte(duplicateJSON))
		if first == nil || second == nil || first.Error() != second.Error() {
			t.Fatalf("duplicate JSON key result=%v/%v", first, second)
		}
	})
	t.Run("unsafe-symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.yaml")
		link := filepath.Join(directory, "manifest.yaml")
		if err := os.WriteFile(target, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := runCheckerPath(t, repoRoot, link); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	t.Run("unsafe-ancestor-symlink", func(t *testing.T) {
		directory := t.TempDir()
		realDirectory := filepath.Join(directory, "real")
		if err := os.Mkdir(realDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realDirectory, "manifest.yaml"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		linkedDirectory := filepath.Join(directory, "linked")
		if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
			t.Fatal(err)
		}
		if err := runCheckerPath(t, repoRoot, filepath.Join(linkedDirectory, "manifest.yaml")); err == nil {
			t.Fatal("ancestor symlink accepted")
		}
	})
	t.Run("unsafe-oversize", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "manifest.yaml")
		if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, 512*1024+1), 0600); err != nil {
			t.Fatal(err)
		}
		if err := runCheckerPath(t, repoRoot, path); err == nil {
			t.Fatal("oversized manifest accepted")
		}
	})
	t.Run("bounded-redacted-diagnostic", func(t *testing.T) {
		canary := strings.Repeat("LONG-CANARY-", 512)
		doc := cloneJSONMap(t, base)
		doc["canonical"].(map[string]any)["cells"].([]any)[0].(map[string]any)["attribute"] = canary
		err := runCheckerMutation(t, repoRoot, doc)
		if err == nil {
			t.Fatal("long-canary mutation accepted")
		}
		if len(err.Error()) > 256 || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "LONG-CANARY") {
			t.Fatalf("diagnostic leaked or exceeded bound: len=%d err=%v", len(err.Error()), err)
		}
	})
}

func cloneJSONMap(t *testing.T, source map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func runCheckerMutation(t *testing.T, repoRoot string, document map[string]any) error {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return runCheckerBytes(t, repoRoot, encoded)
}

func runCheckerBytes(t *testing.T, repoRoot string, data []byte) error {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "manifest.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return runCheckerPath(t, repoRoot, path)
}

func runCheckerPath(t *testing.T, repoRoot, manifestPath string) error {
	t.Helper()
	command := exec.Command("python3", "scripts/check-mapping-manifest.py", manifestPath)
	command.Dir = repoRoot
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
}
