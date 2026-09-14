# Design principles

1. **Receiver-compatible at the input boundary.** Compatibility is a versioned,
   testable schema, not a vague resemblance.
2. **Protocol loss is explicit.** NetFlow v5, v9, and IPFIX have different
   expressiveness. Unsupported or lossy mappings produce defined diagnostics.
3. **State is isolated by destination.** Sequence numbers, observation domains,
   templates, refresh deadlines, and transport failures must not leak between
   configured destinations.
4. **Wire output is independently verifiable.** Golden packets and at least one
   independent decoder or collector validate encoded output.
5. **Bounded resources.** Record size, template count, destination count, queues,
   datagram packing, retries, and cardinality have documented limits.
6. **Collector-native behavior.** Configuration, lifecycle, telemetry, error
   handling, backpressure, and testing follow current Collector conventions.
7. **External component first.** The project matures as its own module and custom
   distribution before any donation proposal.
