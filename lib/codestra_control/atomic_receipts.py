"""Privileged ATOMIC_INCLUSION source ports; never author-supplied authority.

The protected policy reader, SQL issuer principal and independent GitHub client
are administered dependencies. Python values/JSON do not authenticate themselves.
Inclusion certifies history, not current write admission or retained file content.
No CLI, credentials, live provisioning or absent-ref bootstrap is supplied here.
"""
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from urllib.parse import quote

from .publisher_adapter import PublicationDenied, require
from .publisher_acceptance import _unique_object, _utc


@dataclass(frozen=True)
class AtomicPurposePolicy:
    schema: str
    state: str
    accepted_by: str
    acceptance_ref: str
    revision: str
    purpose: str
    repository: str
    repository_id: int
    app_id: int
    installation_id: int
    name: str
    custody_receipt: str
    capability_receipt: str
    max_receipt_lifetime_seconds: int
    max_observation_age_seconds: int
    accepted_at: datetime
    expires_at: datetime


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _instant(value):
    """PostgreSQL timestamptz JSON follows its session zone; compare instants."""
    require(type(value) is str, 'ATOMIC_DATABASE_TIMESTAMP_INVALID')
    try: result = datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError: raise PublicationDenied('ATOMIC_DATABASE_TIMESTAMP_INVALID') from None
    require(result.tzinfo is not None, 'ATOMIC_DATABASE_TIMESTAMP_INVALID')
    return result.astimezone(timezone.utc)


def receipt_digest(payload):
    return hashlib.sha256(b'codestra.atomic-inclusion.v1\0' + canonical(payload).encode()).hexdigest()


def observation_digest(context, check, pr, merge, candidate):
    """Bind immutable authoritative facts; exclude today's moving aggregate ref."""
    facts = dict(check_id=check['id'],suite_id=check['check_suite']['id'],
        app_id=check['app']['id'],name=check['name'],external_id=check['external_id'],
        completed_at=_utc(check['completed_at']).isoformat(),head_sha=check['head_sha'],
        pr_id=pr['id'],pr_number=pr['number'],merged_at=_utc(pr['merged_at']).isoformat(),
        source_ref=pr['head']['ref'],target_ref=pr['base']['ref'],repository_id=pr['base']['repo']['id'],
        merge_sha=merge['sha'],merge_tree=merge['tree']['sha'],parents=[v['sha'] for v in merge['parents']],
        candidate_sha=candidate['sha'],candidate_tree=candidate['tree']['sha'])
    return hashlib.sha256(b'codestra.atomic-observation.v1\0'+canonical(facts).encode()).hexdigest()


def load_atomic_policy(raw, now):
    require(type(raw) is bytes and 0 < len(raw) <= 16384, 'ATOMIC_ACCEPTANCE_BYTES_REQUIRED')
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise PublicationDenied('ATOMIC_ACCEPTANCE_JSON_INVALID') from None
    require(type(value) is dict and set(value) == {field.name for field in fields(AtomicPurposePolicy)},
            'ATOMIC_ACCEPTANCE_SCHEMA_INVALID')
    require(value['schema'] == 'codestra.atomic-inclusion-acceptance.v1' and value['state'] == 'ACCEPTED'
            and value['accepted_by'] == 'Ralph L. Appolon' and value['purpose'] == 'ATOMIC_INCLUSION',
            'ATOMIC_PURPOSE_NOT_ACCEPTED')
    for key in ('repository_id', 'app_id', 'installation_id'):
        require(type(value[key]) is int and value[key] > 0, 'ATOMIC_ACCEPTANCE_IDENTITIES_INVALID')
    require(value['app_id'] != 15368 and type(value['repository']) is str
            and re.fullmatch(r'appolon1908/[A-Za-z0-9][A-Za-z0-9_.-]*', value['repository']),
            'ATOMIC_ACCEPTANCE_IDENTITIES_INVALID')
    for key in ('acceptance_ref', 'revision', 'name', 'custody_receipt', 'capability_receipt'):
        require(type(value[key]) is str and bool(value[key].strip()), 'ATOMIC_ACCEPTANCE_PIN_REQUIRED')
    require(value['name'] not in ('codestra-control-plane', 'codestra/control-plane'), 'ATOMIC_PURPOSE_ALIAS_DENIED')
    require(type(value['max_receipt_lifetime_seconds']) is int and 1 <= value['max_receipt_lifetime_seconds'] <= 86400
            and type(value['max_observation_age_seconds']) is int and 1 <= value['max_observation_age_seconds'] <= 300,
            'ATOMIC_ACCEPTANCE_BOUNDED_LIFETIME_REQUIRED')
    value['accepted_at'] = _utc(value['accepted_at']); value['expires_at'] = _utc(value['expires_at'])
    require(value['accepted_at'] <= now < value['expires_at'], 'ATOMIC_ACCEPTANCE_EXPIRED_OR_FUTURE')
    return AtomicPurposePolicy(**value)


def validate_task_graph(graph):
    require(type(graph) is dict and len(graph) <= 1000 and all(type(k) is str and k for k in graph),
            'ATOMIC_GRAPH_INVALID')
    dependents = {key: set() for key in graph}; counts = {}
    for key, values in graph.items():
        require(type(values) is list and len(values) <= 1000 and all(type(v) is str and v in graph and v != key for v in values)
                and len(set(values)) == len(values), 'ATOMIC_GRAPH_REFERENCE_INVALID')
        counts[key] = len(values)
        for value in values: dependents[value].add(key)
    ready = [key for key, count in counts.items() if count == 0]; visited = 0
    while ready:
        key = ready.pop(); visited += 1
        for dependent in dependents[key]:
            counts[dependent] -= 1
            if counts[dependent] == 0: ready.append(dependent)
    require(visited == len(graph), 'ATOMIC_GRAPH_CYCLE')
    return tuple((key, tuple(sorted(values))) for key, values in sorted(graph.items()))


@dataclass(frozen=True)
class AtomicInclusionReceipt:
    receipt_id: str
    payload_json: str
    check_id: int
    suite_id: int
    external_id: str
    observation_digest: str
    prepared_at: datetime
    completed_at: datetime
    sealed_at: datetime
    expires_at: datetime

    @property
    def payload(self): return json.loads(self.payload_json)


@dataclass(frozen=True)
class AtomicInventory:
    workstation_id: str
    graph: tuple
    receipts: tuple[AtomicInclusionReceipt, ...]
    inventory_digest: str


def read_inventory(cur, acquired, workstation, now):
    """Inside the existing authenticated read-only registry transaction.

    Count pending/inactive mappings too. No caller-provided receipt list, legacy
    PASS, task status or current workstation epoch can hide a required child.
    """
    b = acquired.snapshot.observed_binding
    cur.execute("""SELECT EXISTS(SELECT 1 FROM atomic_receipts.product_grants g JOIN atomic_receipts.principal_integrity r
     ON r.rolname=g.principal AND r.oid=g.role_oid WHERE g.principal=session_user AND g.product=%s
     AND r.restricted AND g.capability='read' AND g.active AND g.expires_at>clock_timestamp())""", (b.product,))
    require(cur.fetchone() == (True,), 'ATOMIC_AUTHENTICATED_PRODUCT_READ_GRANT_REQUIRED')
    cur.execute("""WITH inventory AS (
     SELECT task_id FROM public.atomic_tasks WHERE workstation_id=%s UNION
     SELECT task_id FROM scoped_registration.task_assignments WHERE product=%s AND workstation_id=%s UNION
     SELECT task_id FROM scoped_registration.candidates WHERE product=%s AND workstation_id=%s UNION
     SELECT task_id FROM assignment_leases.bindings WHERE product=%s AND workstation_id=%s UNION
     SELECT b.task_id FROM assignment_leases.coordinator_tasks c JOIN assignment_leases.bindings b USING(binding_id)
      WHERE b.product=%s AND b.workstation_id=%s)
     SELECT i.task_id,to_jsonb(t),to_jsonb(a),to_jsonb(c),to_jsonb(x),to_jsonb(m),to_jsonb(l)
     FROM inventory i LEFT JOIN public.atomic_tasks t USING(task_id)
     LEFT JOIN scoped_registration.task_assignments a USING(task_id)
     LEFT JOIN scoped_registration.candidates c USING(task_id)
     LEFT JOIN assignment_leases.bindings x USING(task_id)
     LEFT JOIN assignment_leases.coordinator_tasks m ON m.binding_id=x.binding_id
     LEFT JOIN scoped_registration.lanes l ON l.kind='candidate' AND l.identity=i.task_id AND l.product=%s
     ORDER BY i.task_id LIMIT 1001""", (workstation,b.product,workstation,b.product,workstation,
                                      b.product,workstation,b.product,workstation,b.product))
    rows = cur.fetchall()
    require(len(rows) <= 1000 and len({row[0] for row in rows}) == len(rows), 'ATOMIC_INVENTORY_AMBIGUOUS')
    inventory = {}; bindings = {}
    for task, t, a, c, x, m, lane in rows:
        require(all(type(v) is dict for v in (t,a,c,x,m,lane)), 'ATOMIC_CANONICAL_CHILD_UNSEALED_OR_UNREGISTERED')
        expected_candidate=dict(product=b.product,workstation_id=workstation,task_id=task,title=m['title'],
            branch=x['source_ref'],target_branch=x['target_ref'],worktree=x['worktree'],head_sha=x['head_sha'],
            base_sha=x['base_sha'],prerequisites=m['prerequisites'])
        require(t['workstation_id'] == workstation and t['owner'] == a['principal'] == c['principal'] == x['principal']
                and a['active'] is True and x['active'] is True and m['active'] is True
                and all(v['product'] == b.product and v['workstation_id'] == workstation for v in (a,c,x))
                and c['branch'] == x['source_ref'] == lane['branch'] and c['worktree'] == x['worktree'] == lane['worktree']
                and x['target_ref'] == b.source_ref and x['repository'] == b.repository
                and x['repository_id'] == acquired.repository_id
                and c['payload'] == expected_candidate and t['title']==m['title'],
                'ATOMIC_CANONICAL_CHILD_DRIFT_OR_REVOKED')
        # Scope prerequisites already have a separate contract. A future adapter
        # must verify nonempty historical prerequisite receipts, never omit them.
        require(m['prerequisites'] == [], 'ATOMIC_HISTORICAL_SCOPE_PREREQUISITES_UNSUPPORTED')
        inventory[task] = (t,a,c,x,m,lane); bindings[x['binding_id']] = task
    cur.execute("""SELECT identity FROM scoped_registration.lanes WHERE product=%s AND kind='candidate'
     AND (branch LIKE %s OR identity=ANY(%s)) ORDER BY identity LIMIT 1001""",
                (b.product, 'atomic/' + b.source_ref.removeprefix('subsection/') + '--%', list(inventory)))
    lane_tasks = [row[0] for row in cur.fetchall()]
    require(len(lane_tasks) == len(inventory) and set(lane_tasks) == set(inventory), 'ATOMIC_ORPHAN_CANDIDATE_LANE')
    cur.execute('SELECT task_id,depends_on FROM atomic_receipts.task_dependencies WHERE product=%s AND workstation_id=%s ORDER BY task_id LIMIT 1001',
                (b.product, workstation))
    graph_rows = cur.fetchall(); graph = dict(graph_rows)
    require(len(graph_rows) == len(graph) and set(graph) == set(inventory), 'ATOMIC_COMPLETE_TASK_GRAPH_REQUIRED')
    edges = validate_task_graph(graph)
    cur.execute("""SELECT to_jsonb(r),to_jsonb(p),to_jsonb(l),to_jsonb(proof),to_jsonb(d),
     EXISTS(SELECT 1 FROM atomic_receipts.revocations v WHERE v.receipt_id=r.receipt_id OR v.binding_id=d.binding_id),
     EXISTS(SELECT 1 FROM atomic_receipts.product_grants g JOIN atomic_receipts.principal_integrity issuer ON issuer.rolname=g.principal AND issuer.oid=g.role_oid
      WHERE g.principal=p.principal AND g.role_oid=p.role_oid AND g.product=%s AND g.capability='issue'
      AND issuer.restricted AND g.active AND g.expires_at>clock_timestamp()),
     EXISTS(SELECT 1 FROM scoped_registration.principals v JOIN atomic_receipts.principal_integrity role ON role.rolname=v.principal AND role.oid=v.role_oid
      JOIN assignment_leases.permissions perm ON perm.principal=v.principal AND perm.product=%s AND perm.capability='attest' AND perm.active
      WHERE v.principal=proof.verifier AND v.role_oid=proof.verifier_oid AND v.active
      AND role.restricted),
     EXISTS(SELECT 1 FROM scoped_registration.principals principal JOIN atomic_receipts.principal_integrity role
      ON role.rolname=principal.principal AND role.oid=principal.role_oid
      JOIN scoped_registration.grants g ON g.principal=principal.principal AND g.product=d.product AND g.capability='candidate'
      WHERE principal.principal=l.principal AND principal.role_oid=l.principal_oid AND principal.active AND role.restricted
      AND g.repository=p.payload->'binding'->>'repository') AND d.active
     FROM atomic_receipts.receipts r JOIN atomic_receipts.preparations p USING(preparation_id)
     JOIN atomic_receipts.delegations d USING(delegation_id)
     JOIN assignment_leases.leases l ON l.lease_id=d.lease_id
     JOIN assignment_leases.proofs proof ON proof.proof_id=(p.payload->'proof'->>'proof_id')::uuid
     WHERE d.product=%s AND p.payload->'binding'->>'workstation_id'=%s
     ORDER BY r.receipt_id LIMIT 1001""", (b.product,b.product,b.product,workstation))
    receipts = []; represented = set()
    for raw, prepared, lease, proof, current_delegation, revoked, issuer_active, verifier_active, builder_active in cur.fetchall():
        payload = prepared['payload']; frozen = payload['binding']; task = frozen['task_id']
        require(task in inventory and task not in represented and frozen == inventory[task][3]
                and payload['delegation']==current_delegation
                and revoked is False and issuer_active is True and verifier_active is True and builder_active is True,
                'ATOMIC_RECEIPT_REVOKED_EXTRA_OR_CHANGED')
        represented.add(task)
        issuance = payload['lease']; materializer = payload['proof']; delegation = payload['delegation']
        start = _instant(prepared['prepared_at']); sealed = _instant(raw['sealed_at'])
        require(payload['purpose'] == delegation['purpose'] == 'ATOMIC_INCLUSION'
                and prepared['authentication'] == 'scram-sha-256:' + prepared['principal']
                and prepared['principal'] == delegation['principal'] and prepared['role_oid'] == delegation['role_oid']
                and prepared['principal'] not in (issuance['principal'],materializer['verifier'])
                and materializer == proof and materializer['consumed'] is True
                and materializer['verifier_authentication'] == 'scram-sha-256:' + materializer['verifier']
                and materializer['verifier'] != issuance['principal']
                and materializer['binding_snapshot'] == issuance['binding_snapshot'] == frozen
                and issuance['state'] == 'ACTIVE' and lease['state'] in ('ACTIVE','RELEASED')
                and all(lease[key] == issuance[key] for key in ('lease_id','binding_id','workstation_id','principal','principal_oid','epoch','started_at','binding_snapshot'))
                and issuance['epoch'] == delegation['epoch'] and issuance['lease_id'] == delegation['lease_id']
                and _instant(issuance['started_at']) <= start <= sealed < _instant(issuance['expires_at'])
                and _instant(materializer['issued_at']) <= start <= sealed < _instant(materializer['expires_at'])
                and payload['task_dependencies'] == dict(product=b.product,workstation_id=workstation,task_id=task,depends_on=graph[task])
                and now < _instant(raw['expires_at']) <= _instant(payload['issue_grant_expires_at']), 'ATOMIC_SEALED_ISSUANCE_INVALID')
        require(raw['external_id'] == receipt_digest(payload), 'ATOMIC_PURPOSE_DIGEST_MISMATCH')
        receipts.append(AtomicInclusionReceipt(raw['receipt_id'],canonical(payload),raw['check_id'],raw['suite_id'],
            raw['external_id'],raw['observation_digest'],start,_instant(raw['completed_at']),sealed,_instant(raw['expires_at'])))
    require(represented == set(inventory), 'ATOMIC_CANONICAL_CHILD_UNSEALED_OR_UNREGISTERED')
    if not inventory: return None
    digest = receipt_digest(dict(inventory=inventory, graph=edges,
        receipts=[(r.receipt_id,r.external_id) for r in receipts]))
    return AtomicInventory(workstation,edges,tuple(receipts),digest)


def verify_inclusions(api, policy_reader, acquired, contract, inventory, now):
    require(policy_reader is not None, 'ATOMIC_ACCEPTANCE_UNCONFIGURED')
    try: policy = load_atomic_policy(policy_reader(), now)
    except PublicationDenied: raise
    except Exception: raise PublicationDenied('ATOMIC_ACCEPTANCE_UNAVAILABLE') from None
    a = acquired.authority; b = acquired.snapshot.observed_binding
    require(policy.repository == b.repository and policy.repository_id == acquired.repository_id
            and policy.app_id == a.app_id and policy.installation_id == a.installation_id
            and policy.app_id != contract.publisher_app_id and policy.name != contract.certificate_name
            and policy.custody_receipt == a.custody_receipt, 'ATOMIC_PURPOSE_IDENTITY_OR_SCOPE_MISMATCH')
    api.assert_identity(a, acquired.repository_id, now)
    deadline = min(policy.expires_at, acquired.snapshot.observed_at + timedelta(seconds=policy.max_observation_age_seconds))
    require(now < deadline, 'ATOMIC_FRESH_OBSERVATION_REQUIRED')
    parent_path = f'/repos/{b.repository}/branches/{quote(b.source_ref,safe="")}'
    parent = api.get(parent_path)
    require(parent['commit']['sha'] == b.source_sha, 'ATOMIC_AGGREGATE_PARENT_MOVED')
    merges = {}
    for receipt in inventory.receipts:
        payload = receipt.payload; context = payload['delegation']['context']; bound = payload['binding']
        expected = dict(purpose='ATOMIC_INCLUSION',repository=b.repository,repository_id=acquired.repository_id,
            task_id=bound['task_id'],source_ref=bound['source_ref'],target_ref=b.source_ref,
            head_sha=bound['head_sha'],base_sha=bound['base_sha'],app_id=policy.app_id,
            installation_id=policy.installation_id,name=policy.name,policy_revision=policy.revision,
            custody_receipt=policy.custody_receipt,capability_receipt=policy.capability_receipt)
        require(all(context.get(k) == v for k,v in expected.items()), 'ATOMIC_RECEIPT_ACCEPTANCE_PINS_MISMATCH')
        for key in ('candidate_sha','candidate_tree','merge_sha','merge_tree'):
            require(type(context.get(key)) is str and re.fullmatch('[0-9a-f]{40}',context[key])
                    and context[key] != '0'*40, 'ATOMIC_EXACT_CANDIDATE_REQUIRED')
        require(all(type(context.get(k)) is int and context[k] > 0 for k in ('pr_number','pr_id'))
                and receipt.prepared_at <= receipt.completed_at <= receipt.sealed_at < receipt.expires_at
                and policy.accepted_at <= receipt.prepared_at and now < receipt.expires_at
                and receipt.expires_at <= receipt.sealed_at + timedelta(seconds=policy.max_receipt_lifetime_seconds),
                'ATOMIC_SEALED_RECEIPT_LIFETIME_INVALID')
        check = api.get(f'/repos/{b.repository}/check-runs/{receipt.check_id}')
        require(type(check.get('id')) is int and check['id'] == receipt.check_id
                and type(check.get('app',{}).get('id')) is int and check['app']['id'] == policy.app_id
                and check.get('name') == policy.name and check.get('head_sha') == context['candidate_sha']
                and check.get('external_id') == receipt.external_id and check.get('status') == 'completed'
                and check.get('conclusion') == 'success' and _utc(check.get('completed_at')) == receipt.completed_at
                and check.get('check_suite',{}).get('id') == receipt.suite_id, 'ATOMIC_ONLINE_RECEIPT_UNVERIFIED')
        suite = api.get(f'/repos/{b.repository}/check-suites/{receipt.suite_id}')
        require(type(suite.get('id')) is int and suite['id'] == receipt.suite_id
                and type(suite.get('app',{}).get('id')) is int and suite['app']['id'] == policy.app_id
                and suite.get('head_sha') == context['candidate_sha'] and suite.get('status') == 'completed'
                and suite.get('conclusion') == 'success', 'ATOMIC_ONLINE_SUITE_UNVERIFIED')
        pr = api.get(f'/repos/{b.repository}/pulls/{context["pr_number"]}')
        require(type(pr.get('id')) is int and pr['id'] == context['pr_id']
                and type(pr.get('number')) is int and pr['number'] == context['pr_number']
                and pr.get('merged') is True and pr.get('state') == 'closed' and pr.get('merge_commit_sha') == context['merge_sha']
                and pr.get('head',{}).get('ref') == bound['source_ref'] and pr['head'].get('sha') == context['candidate_sha']
                and pr['head'].get('repo',{}).get('id') == acquired.repository_id
                and pr.get('base',{}).get('ref') == b.source_ref and pr['base'].get('repo',{}).get('id') == acquired.repository_id
                and _utc(pr.get('merged_at')) <= receipt.prepared_at, 'ATOMIC_MERGED_PR_UNVERIFIED')
        merge = api.get(f'/repos/{b.repository}/git/commits/{context["merge_sha"]}')
        candidate = api.get(f'/repos/{b.repository}/git/commits/{context["candidate_sha"]}')
        require(merge.get('sha') == context['merge_sha'] and merge.get('tree',{}).get('sha') == context['merge_tree']
                and [v['sha'] for v in merge.get('parents',[])] == [bound['base_sha'],context['candidate_sha']]
                and candidate.get('sha') == context['candidate_sha'] and candidate.get('tree',{}).get('sha') == context['candidate_tree'],
                'ATOMIC_MERGE_PARENTS_OR_TREE_UNVERIFIED')
        require(receipt.observation_digest == observation_digest(context,check,pr,merge,candidate),
                'ATOMIC_IMMUTABLE_OBSERVATION_CHANGED')
        comparison = api.get(f'/repos/{b.repository}/compare/{context["merge_sha"]}...{b.source_sha}')
        require(comparison.get('status') in ('ahead','identical')
                and comparison.get('merge_base_commit',{}).get('sha') == context['merge_sha'], 'ATOMIC_INCLUSION_NOT_ANCESTOR')
        require(api.get(f'/repos/{b.repository}/branches/{quote(bound["source_ref"],safe="")}')['commit']['sha'] == context['candidate_sha'],
                'ATOMIC_SOURCE_REF_MOVED')
        merges[bound['task_id']] = (context['merge_sha'],receipt)
        deadline = min(deadline,receipt.expires_at)
    for task, prerequisites in inventory.graph:
        for prerequisite in prerequisites:
            earlier, previous = merges[prerequisite]; later, following = merges[task]
            require(previous.sealed_at <= following.prepared_at, 'ATOMIC_PREREQUISITE_NOT_PREVIOUSLY_SEALED')
            comparison = api.get(f'/repos/{b.repository}/compare/{earlier}...{later}')
            require(comparison.get('status') == 'ahead' and comparison.get('merge_base_commit',{}).get('sha') == earlier,
                    'ATOMIC_PREREQUISITE_NOT_INCLUDED')
    require(api.get(parent_path) == parent, 'ATOMIC_AGGREGATE_PARENT_MOVED')
    return deadline
