# Publisher inventory source repair

The canonical publisher now collects all open-PR pages before evaluating or
publishing for a repository. Each page contains at most 100 entries; a short
terminal page is required within 100 pages. Invalid entries, duplicate PR IDs,
API failures and pagination exhaustion refuse the partial inventory. Rate limits
still stop the cycle without retry. GitHub pagination is not an atomic snapshot;
this change does not establish authenticated promotion evidence.

The existing canonical source already selects the explicitly approved 43 repos,
checks additional registry mappings, reconciles the latest status before appending,
and paginates status history with a fail-closed bound. Those mechanisms and all
coverage/exception lists remain unchanged. The six-repository installed publisher
is separate deployed source; this task does not install the canonical publisher.

Known operational gaps remain: competing publishers sharing `codestra/control-plane`
need an independently accepted ownership/serialization contract. This source has
no authenticated ownership adapter and must not be deployed as proof that one
exists. Duplicate suppression cannot prevent concurrent writers. An exhausted
GitHub per-context status history cannot be repaired by retrying, deleting local
state, renaming the context or bypassing required checks; unchanged results are
already suppressed, and changed results can still be refused by GitHub.

The canonical historical `legacy/bin/github-status-sync` also contains shared-context
publication, standalone bootstrap success, account-wide discovery and a ledger
remote-SHA UPDATE. Those behaviors are outside this narrow inventory repair;
securing or retiring that writer requires an independently approved authority
contract and migration review. Installed publisher digests differ from the
canonical source. No installed daemon was executed.
No new repos are added based on the 13-repository audit. No statuses, assignments,
leases, grants, refs or production configuration were written. This is source-only
preparation, not certification or activation.
