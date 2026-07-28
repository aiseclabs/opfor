# Chain-Class Knowledge

The attack-surface chain class reads its judgment and detection knowledge from this tree. The tree
holds two kinds of unit, told apart by who decides, a model or a capability:

- Judgment, model-read. The prose the triage model reads to weigh whether a swept contract is worth
  a manual audit and how urgently, and the role fingerprints the identify seam reads as a guide. The
  verdict and the role stay the model's, the data is a guide it weighs, not a mechanical match.
- Detection, deterministic. The mechanical patterns an enrichment capability applies to a contract's
  source, the fund-path vocabulary, the access guards, the risk signatures. A capability matches
  these and reports what hit, no model in the loop, triage decides what a hit is worth, invariant 1.

The tree:

- `findings/` one file per audit-worthiness class the triage model weighs, the body its judgment
  prose, how a class moves an audit priority, the funds floor, the user-reachable fund path, the
  complex-dependency bar. It covers the external fund path, the complex fund accounting, the
  untrusted dependency, the upgradeable proxy surface, the centralization risk that is recorded but
  never raises external-attacker priority, and the unverified-high-value balance surfaced on its own
  since code cannot read to grade it.
- `technologies/` the role fingerprints the identify seam reads as a guide, so a role is recognized
  from a known template's marker functions rather than guessed. `roles.yaml` is one entry per role,
  the fund-management roles, vault, staking, farm, lending, locker, presale, the router and proxy
  surfaces, and the downgraded DEX-layer pool and token. `vendored-libraries.yaml` marks the
  copied-in library code a source fingerprint folds into its own project rather than counts as a
  distinct target.
- `detections/contract-signals/` the mechanical detection data the enrichment capabilities apply,
  not judgment. `interfaces.yaml` is the fund-path function vocabulary and the access-guard keywords
  the `enum_interfaces` capability applies. `risk-signals.yaml` is the external-attacker source
  signatures the `scan_signals` capability matches, such as share accounting, oracle dependency, and
  delegatecall. `centralization-signals.yaml` is the owner-power signatures, kept apart so they never
  raise the audit priority.
- `chains.yaml` the per-chain sweep policy the sweep, pivot, and funds read, the chain id, the
  discovery slug, the value tokens and their pricing, the burn sinks skipped as funds, and the raw
  DEX-layer roles the pivot reaches past. `known-infrastructure.yaml` the audited bluechip addresses
  triage and the report drop from the audit queue rather than flag, keeping the queue on the unknown
  long tail.

This is the only index in the tree. Each subdirectory carries its files directly with no
per-directory index, matching the codejury convention of a single knowledge index.

Adding knowledge is a new or extended file here, never an engine, capability, or triage code change,
invariant 1.
