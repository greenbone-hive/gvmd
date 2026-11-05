# Experimental multi-target scan groups

This companion controller drives one logical GSA task across selected source
targets. It expands explicit hosts for validation, then creates **one scanner
target and child task per selected source target**, preserving the target's
ports and credentials. The logical task appears as a normal gvmd task record;
a completed run publishes a combined report while retaining source reports.

The service uses python-gvm and a Unix gvmd socket. Run it only behind the
GSAD-authenticated reverse proxy in the matching experimental GSAD branch.
The `TRUST_GSA_PROXY=1` mode assumes the proxy alone can reach port 8080.
Configure a distinct, non-default `REVIEW_USERNAME` and `REVIEW_PASSWORD`
for designated scan-group operators. The service refuses all requests when
either is empty. The matching proxy first validates the GSAD session, then
passes HTTP Basic operator credentials to the controller. Operators enter
`username:password` when GSA prompts. These operator credentials grant
access to the shared GMP inventory and every review group; deploy this review
service only for operators authorized for that scope.
Source targets must contain explicit IP addresses. DNS names are rejected
before a scan plan is created because native reports identify hosts by IP.
Persistent group state lives in `REVIEW_DB` (SQLite).

Credential overrides are rejected in this tier. `test_controller.py` checks
six hosts across two targets produce exactly two child tasks.

This is a separate experimental controller. Native gvmd multi-target storage,
launch, resume, and report aggregation are not implemented by this directory.
