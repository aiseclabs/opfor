---
cpe: apache:airflow
markers:
  - static/dist/airflowdefaulttheme
probe_paths:
  - /login/
---

# Apache Airflow

Verified against Airflow 2.9. The root redirects unauthenticated to `/login/`, whose sign-in page
links the app theme asset `/static/dist/airflowDefaultTheme.<hash>.css`, a high-signal marker a
page merely mentioning Airflow does not carry, unlike the bare word. The trailing-slash `/login/`
is the served form, `/login` permanent-redirects to it, so the path set probes both. No version is
exposed unauthenticated, the sign-in page, the `/health` JSON, and the response headers all omit
it, so Airflow is identified without a version.
