// Package mapping compiles the receiver's canonical records into immutable
// protocol shapes and performs one synchronous record binding.  Configuration
// is intentionally a small static boundary: no Collector configuration,
// dynamic templates, or retained pdata is involved here.
package mapping
