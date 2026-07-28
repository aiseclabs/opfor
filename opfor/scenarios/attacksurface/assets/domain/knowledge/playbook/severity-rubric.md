---
title: Severity rubric
---

# Severity Rubric

One scale for every finding class, so a verdict is graded the same whichever class mints it.
The judge grades on the evidence in the report, never on a path or a name alone, and a finding
class adds only the nuance its own surface needs.

## The Scale

- CRITICAL. An unauthenticated path to code execution, a full authentication bypass, or a read
  of secrets or bulk sensitive data, reachable now without a credential.
- HIGH. An unauthenticated management, write, or administrative surface, a known vulnerability
  that fits the exposed surface and needs no credential, or a takeover of a live name, which
  hands an attacker a trusted subdomain.
- MEDIUM. A surface whose nature warrants review before a specific flaw is proven, such as an
  administrative or non-production interface, an API specification or an introspection schema
  that maps the surface, or an identified open-source console whose exposure is not yet shown to
  grant an action.
- LOW. A read-only information leak, a version banner, a metrics page, or a declared but
  unverified exposure whose operations were gated or were not probed.
- INFO. A fact worth recording that is not itself a weakness, such as a host correctly behind a
  gate, an inventory note, or a degraded chunk that names what was not judged.

## What Moves A Grade

- Reachability decides more than any other axis. The same weakness reachable without a
  credential outranks one behind a login or a zero-trust gate. A gated instance is low or
  informational even when the weakness is otherwise severe, note it rather than raising it.
- Verified outranks declared. A specification, a schema, or a version banner declares a
  surface, it does not prove an operation answers or that an instance is exploitable, so a
  declared but unproven exposure caps at low. Grade up only on what a safe read confirmed.
- What the surface grants sets the ceiling. A read that returns data anyone can take outranks a
  page that only names a product, and a write or a state change outranks a read.
- Sensitivity raises a grade. Secrets, configuration, or bulk personal data reachable
  unauthenticated is the strongest case.

## Recall First

When a finding is real, never drop it for a low impact, grade it low and keep it. A missed low
is a silent gap, a reported low is a visible one an operator can dismiss. The doubt that
belongs to a false positive is settled by the false-positive traps, not by lowering a severity
to hide an uncertain call.
