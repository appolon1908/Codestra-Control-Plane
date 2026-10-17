"""Read-only effective branch policy. Unavailable/bypass-opaque evidence denies."""
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import quote
from .publisher_adapter import require,PublicationDenied,CONTEXTS
from .publisher_github import APIUnavailable

@dataclass(frozen=True)
class ProtectionObservation:
    approvals:int
    codeowner:bool
    stale:bool
    last_push:bool
    conversations:bool
    strict:bool
    checks:tuple
    evidence_digest:str


def _count(value):
    require(type(value) is int and value>=0,'INVALID_REVIEW_COUNT')
    return value


def _boolean(value):
    require(type(value) is bool,'INVALID_PROTECTION_BOOLEAN')
    return value


def _check(context,app_id):
    require(type(context) is str and bool(context.strip()) and len(context)<=255,'INVALID_REQUIRED_CONTEXT')
    require(type(app_id) is int and app_id>0,'UNBOUND_REQUIRED_CHECK_PRODUCER')
    return context,app_id


def observe_protection(api,repo,branch):
    try:
        return _observe_protection(api,repo,branch)
    except (KeyError,TypeError,ValueError,AttributeError):
        raise PublicationDenied('MALFORMED_EFFECTIVE_PROTECTION') from None


def _observe_protection(api,repo,branch):
    require(type(repo) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*',repo),'INVALID_PROTECTION_REPOSITORY')
    from .policy import valid_ref
    require(valid_ref(branch),'INVALID_PROTECTION_BRANCH')
    try:
        classic=api.get(f'/repos/{repo}/branches/{quote(branch,safe="")}/protection')
    except APIUnavailable as exc:
        require(exc.status==404,'CLASSIC_PROTECTION_UNAVAILABLE')
        classic=None
    rules=api.effective_rules(repo,branch)
    require(type(rules) is list,'EFFECTIVE_RULES_UNAVAILABLE')
    approvals=0;owner=stale=last=threads=strict=False;checks=set();details={};seen=set()
    if classic is not None:
        require(type(classic) is dict and classic['enforce_admins']['enabled'] is True,'ADMIN_PROTECTION_NOT_ENFORCED')
        reviews=classic['required_pull_request_reviews'];status=classic['required_status_checks']
        bypass=reviews.get('bypass_pull_request_allowances')
        require(type(bypass) is dict and set(bypass)=={'users','teams','apps'}
                and all(type(v) is list and not v for v in bypass.values()),'CLASSIC_REVIEW_BYPASS_UNVERIFIABLE')
        approvals=_count(reviews['required_approving_review_count'])
        owner=_boolean(reviews['require_code_owner_reviews']);stale=_boolean(reviews['dismiss_stale_reviews'])
        last=_boolean(reviews['require_last_push_approval'])
        threads=_boolean(classic['required_conversation_resolution']['enabled']);strict=_boolean(status['strict'])
        require(type(status['checks']) is list,'INVALID_CLASSIC_REQUIRED_CHECKS')
        for check in status['checks']:
            item=_check(check['context'],check['app_id'])
            require(item not in checks,'DUPLICATE_REQUIRED_CHECK');checks.add(item)
    for rule in rules:
        require(type(rule) is dict,'INVALID_EFFECTIVE_RULE')
        rid=rule['ruleset_id'];source_type=rule['ruleset_source_type'];source=rule['ruleset_source'];kind=rule['type']
        require(type(rid) is int and rid>0 and source_type in ('Repository','Organization'),'UNSUPPORTED_RULESET_SOURCE')
        require(source==(repo if source_type=='Repository' else repo.split('/')[0]),'RULESET_SOURCE_MISMATCH')
        key=(rid,kind)
        require(key not in seen,'DUPLICATE_EFFECTIVE_RULE');seen.add(key)
        if rid not in details:
            detail=api.get(f'/repos/{repo}/rulesets/{rid}?includes_parents=true')
            require(type(detail) is dict and type(detail['id']) is int and detail['id']==rid and detail['source_type']==source_type
                    and detail['source']==source and detail['target']=='branch'
                    and detail['enforcement']=='active','RULESET_PROVENANCE_MISMATCH')
            bypass=detail.get('bypass_actors')
            require(type(bypass) is list and not bypass,'RULESET_BYPASS_UNVERIFIABLE')
            require(type(detail['rules']) is list,'RULESET_RULES_UNAVAILABLE')
            details[rid]=detail
        detail=details[rid]
        require(detail['source_type']==source_type and detail['source']==source,'RULESET_SOURCE_MISMATCH')
        matches=[v for v in detail['rules'] if v.get('type')==kind]
        require(len(matches)==1 and matches[0].get('parameters')==rule.get('parameters'),'RULESET_RULE_MISMATCH')
        if kind=='required_linear_history':
            # GitHub enforces this additional history restriction. Its complete
            # provenance and rule detail are verified above and remain digested.
            require(rule.get('parameters') in (None,{}),'UNSUPPORTED_LINEAR_HISTORY_PARAMETERS')
            continue
        if kind in ('deletion','non_fast_forward'):continue
        require(kind in ('pull_request','required_status_checks'),'UNSUPPORTED_EFFECTIVE_RULE')
        p=rule['parameters']
        require(type(p) is dict,'INVALID_RULE_PARAMETERS')
        if kind=='pull_request':
            approvals=max(approvals,_count(p['required_approving_review_count']))
            owner|=_boolean(p['require_code_owner_review']);stale|=_boolean(p['dismiss_stale_reviews_on_push'])
            last|=_boolean(p['require_last_push_approval']);threads|=_boolean(p['required_review_thread_resolution'])
        else:
            strict|=_boolean(p['strict_required_status_checks_policy'])
            require(type(p['required_status_checks']) is list and bool(p['required_status_checks']),'EMPTY_REQUIRED_STATUS_RULE')
            local=set()
            for check in p['required_status_checks']:
                item=_check(check['context'],check['integration_id'])
                require(item not in local,'DUPLICATE_REQUIRED_CHECK');local.add(item);checks.add(item)
    require(classic is not None or bool(rules),'EFFECTIVE_PROTECTION_ABSENT')
    # Canonical ordering avoids false drift from response ordering alone.
    ordered=sorted(rules,key=lambda v:(v['ruleset_id'],v['type']))
    raw={'repository':repo,'branch':branch,'classic':classic,'effective_rules':ordered,'rulesets':details}
    digest=hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return ProtectionObservation(approvals,owner,stale,last,threads,strict,tuple(sorted(checks)),digest)


def validate_protection(observed,approvals,required_checks,publisher_app_id,controller_contexts):
    require(type(observed) is ProtectionObservation,'UNTRUSTED_PROTECTION_OBSERVATION')
    require(type(approvals) is int and approvals>0 and observed.approvals==approvals
            and all((observed.codeowner,observed.stale,observed.last_push,observed.conversations,observed.strict)),
            'PROTECTION_CONTRACT_UNENFORCED')
    require(type(publisher_app_id) is int and publisher_app_id>0,'PUBLISHER_APP_UNCONFIGURED')
    require(type(controller_contexts) is tuple and bool(controller_contexts)
            and len(set(controller_contexts))==len(controller_contexts)
            and set(controller_contexts)<=set(CONTEXTS),'CONTROLLER_PRODUCER_CONTRACT_UNCONFIGURED')
    controller={(name,app) for name,app in observed.checks if name in CONTEXTS}
    require(controller=={(name,publisher_app_id) for name in controller_contexts},'CONTROLLER_CHECK_PRODUCER_MISMATCH')
    from .decision import CONTROL_PLANE_CONTEXTS
    actual={(name,'github-actions:'+str(app)) for name,app in observed.checks if name not in CONTROL_PLANE_CONTEXTS}
    require(actual==required_checks,'REQUIRED_CHECK_PROTECTION_DRIFT')
