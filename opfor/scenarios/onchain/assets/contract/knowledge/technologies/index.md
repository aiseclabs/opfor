# Technologies

Known contract fingerprints, so a role is identified from a signature before a model is asked, and a
standard or bluechip contract is recognized and downgraded. Today the role signatures live in the
`identify` seam as the class's own data. Moving them here, a data file per known template, is the
same increment the domain class already made, tracked in the design doc.

Planned entries.

- Standard AMM pair templates, the PancakeSwap v2 and v3 pair, so a swept pool is recognized as the
  low-value layer and downgraded rather than reported on its own.
- OpenZeppelin proxy patterns, so an upgradeable surface is identified by its fingerprint.
- Common staking and vault templates, so a known-safe fork is not read as a novel target.
