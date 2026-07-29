---
title: SAML Single Sign-On
kind: protocol
detect:
  markers: ["samlrequest", "samlresponse", "/adfs/", "/simplesaml/", "urn:oasis:names:tc:saml", entitydescriptor, federationmetadata]
---

# SAML Single Sign-On

An enterprise single sign-on protocol that gates an application behind a separate identity provider,
the same delegated-authentication role OAuth plays for consumer sign-in. A host wired to SAML
bounces an unauthenticated request to its identity provider carrying a `SAMLRequest`, and the
provider posts a signed assertion back. On recon the question is the one every gate poses, whether it
truly covers the whole host or only the routes the application chooses to send through it.

## On The Recon Surface

- A `302` or `303` redirect, or an auto-submitting form, carrying a `SAMLRequest` to an identity
  provider such as an ADFS `/adfs/ls/` endpoint or a SimpleSAMLphp `/simplesaml/` module, marks a
  gated host.
- A service-provider or identity-provider metadata document, an `EntityDescriptor` under the
  `urn:oasis:names:tc:SAML` namespace, often at an ADFS `FederationMetadata.xml` path, enumerates
  entity ids, assertion-consumer endpoints, and signing certificates, useful orientation and
  occasionally an internal detail leak.
- A `SAMLResponse` posted back to an assertion-consumer path names where the assertion lands, the
  route to weigh for whether it holds.

## How To Read It

A redirect to an identity provider carrying a `SAMLRequest` is the gate doing its job, so the host is
gated, not exposed. The judgment is coverage. A per-request proxy in front of the whole host reads
differently from an application login that covers only the routes the application forwards, so an API
or a background route may skip it. Distinguish the two by whether a sensitive route answers content
rather than a redirect, not by the presence of the redirect alone. This run reads the surface and
never completes a sign-on, so a signature or assertion flaw is out of reach here, judge only what
answers.

## Feeds

- `improper-authentication`, a SAML gate that appears present but does not cover the whole host, or a
  route that answers content while the rest redirects to the identity provider.
- `information-exposure`, metadata that leaks internal entity ids, assertion-consumer endpoints, or
  issuer detail beyond what a public service provider must publish.

## Traps

- A redirect to an identity provider with a `SAMLRequest` is the gate working, report at most INFO
  that the host is gated. Raise it only when a route answers real content instead of the redirect.
- Service-provider metadata is meant to be shared with the identity provider, so a served
  `EntityDescriptor` is at most a map, never an exposure on its own.
