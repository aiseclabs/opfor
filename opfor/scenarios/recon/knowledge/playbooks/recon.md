# Playbook: surface discovery

1. For each seed root, query certificate transparency for names under it. This is
   passive and returns every depth at once, so there is no need to recurse.
2. For every domain found, read its root over HTTP once. Note whether it
   responds, the status, and the server and framework headers.
3. Read the stack from the headers. A `Server` of nginx or Apache, an
   `X-Powered-By` of Express or PHP, a framework banner, all narrow down what the
   host is and what to check next.
4. Names carry signal. A subdomain called admin, dev, staging, internal, vpn, or
   git is worth a closer look in a later pass.
5. Stop when querying and probing stop surfacing anything new.
