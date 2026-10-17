"""Effective policy fixtures are synthetic, never installed repository policy."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
from codestra_control.effective_protection import observe_protection, validate_protection
from codestra_control.publisher_github import APIUnavailable
from codestra_control.publisher_adapter import PublicationDenied

REPO='appolon1908/example'
BRANCH='section/example'

def pull_rule():
    return {'type':'pull_request','parameters':{'required_approving_review_count':1,
      'require_code_owner_review':True,'dismiss_stale_reviews_on_push':True,
      'require_last_push_approval':True,'required_review_thread_resolution':True}}

def checks_rule():
    return {'type':'required_status_checks','parameters':{'strict_required_status_checks_policy':True,
      'required_status_checks':[{'context':'quality','integration_id':123},
                                {'context':'codestra-control-plane','integration_id':7}]}}

class API:
    def __init__(self):
        self.classic=None
        self.rules=[dict(rule,ruleset_id=42,ruleset_source_type='Repository',ruleset_source=REPO)
                    for rule in (pull_rule(),checks_rule())]
        self.detail={'id':42,'target':'branch','source_type':'Repository','source':REPO,
                     'enforcement':'active','bypass_actors':[], 'rules':[pull_rule(),checks_rule()]}
        self.calls=[]
    def get(self,path):
        self.calls.append(path)
        if path.endswith('/protection'):
            if self.classic is None:raise APIUnavailable(404)
            return deepcopy(self.classic)
        if '/rulesets/42?' in path:return deepcopy(self.detail)
        raise AssertionError(path)
    def effective_rules(self,repo,branch):
        self.calls.append(('effective',repo,branch));return deepcopy(self.rules)

class EffectiveProtectionTests(unittest.TestCase):
    def setUp(self):self.api=API()
    def check(self):
        value=observe_protection(self.api,REPO,BRANCH)
        validate_protection(value,1,{('quality','github-actions:123')},7,('codestra-control-plane',))
        return value
    def test_ruleset_only_protection_preserves_required_gates(self):
        value=self.check()
        self.assertEqual(value.checks,(('codestra-control-plane',7),('quality',123)))
    def test_classic_only_is_supported(self):
        self.api.rules=[]
        self.api.classic={'enforce_admins':{'enabled':True},'required_status_checks':{
         'strict':True,'checks':[{'context':'quality','app_id':123},{'context':'codestra-control-plane','app_id':7}]},
         'required_pull_request_reviews':{'required_approving_review_count':1,'require_code_owner_reviews':True,
          'dismiss_stale_reviews':True,'require_last_push_approval':True,
          'bypass_pull_request_allowances':{'users':[],'teams':[],'apps':[]}},
         'required_conversation_resolution':{'enabled':True}}
        self.check()
    def test_missing_or_nonempty_bypass_evidence_denies(self):
        for bypass in (None,[{'actor_type':'Integration','actor_id':7,'bypass_mode':'always'}]):
            with self.subTest(bypass=bypass):
                if bypass is None:self.api.detail.pop('bypass_actors',None)
                else:self.api.detail['bypass_actors']=bypass
                with self.assertRaises(PublicationDenied):self.check()
    def test_disabled_parent_source_or_rule_mismatch_denies(self):
        for key,value in [('enforcement','evaluate'),('source','other/repo'),('source_type','Enterprise'),('rules',[])]:
            original=deepcopy(self.api.detail);self.api.detail[key]=value
            with self.subTest(key=key),self.assertRaises(PublicationDenied):self.check()
            self.api.detail=original
    def test_missing_review_boolean_strictness_or_app_binding_denies(self):
        for index,key,value in [(0,'require_last_push_approval',False),(0,'required_review_thread_resolution',False),
                                (1,'strict_required_status_checks_policy',False)]:
            old=deepcopy(self.api.rules);details=deepcopy(self.api.detail)
            self.api.rules[index]['parameters'][key]=value
            self.api.detail['rules'][index]['parameters'][key]=value
            with self.subTest(key=key),self.assertRaises(PublicationDenied):self.check()
            self.api.rules=old;self.api.detail=details
        for app in (None,-1,True,999):
            self.api.rules[1]['parameters']['required_status_checks'][1]['integration_id']=app
            self.api.detail['rules'][1]['parameters']['required_status_checks'][1]['integration_id']=app
            with self.subTest(app=app),self.assertRaises(PublicationDenied):self.check()
    def test_conflicting_duplicate_and_unsupported_requirements_deny(self):
        for extra in [deepcopy(self.api.rules[0]),dict(self.api.rules[0],type='merge_queue')]:
            self.api.rules.append(extra)
            with self.assertRaises(PublicationDenied):self.check()
            self.api.rules.pop()
    def test_organization_parent_rules_are_observed(self):
        self.api.detail.update(source_type='Organization',source='appolon1908')
        for rule in self.api.rules:rule.update(ruleset_source_type='Organization',ruleset_source='appolon1908')
        self.check()
        self.assertTrue(any(isinstance(p,str) and 'includes_parents=true' in p for p in self.api.calls))
    def test_forbidden_classic_is_not_absent_classic(self):
        original=self.api.get
        def get(path):
            if path.endswith('/protection'):raise APIUnavailable(403)
            return original(path)
        self.api.get=get
        with self.assertRaises(PublicationDenied):self.check()
    def test_policy_drift_changes_observation(self):
        old=self.check()
        self.api.detail['name']='changed metadata'
        self.assertNotEqual(old,observe_protection(self.api,REPO,BRANCH))
    def test_no_protection_and_unbound_quality_check_deny(self):
        self.api.rules=[]
        with self.assertRaises(PublicationDenied):self.check()
        self.setUp()
        self.api.rules[1]['parameters']['required_status_checks'][0]['integration_id']=None
        self.api.detail['rules'][1]['parameters']['required_status_checks'][0]['integration_id']=None
        with self.assertRaises(PublicationDenied):self.check()

    def test_malformed_rule_schema_is_a_structured_denial(self):
        self.api.rules[0].pop('parameters')
        self.api.detail['rules'][0].pop('parameters')
        with self.assertRaises(PublicationDenied):self.check()

    def test_classic_and_rulesets_combine_without_dropping_checks(self):
        native=self.api.rules
        self.test_classic_only_is_supported()
        self.api.rules=native
        self.api.classic['required_status_checks']['checks']=[{'context':'quality','app_id':123}]
        self.api.classic['required_pull_request_reviews']['require_last_push_approval']=False
        self.check()
        extra={'context':'new-required','app_id':456}
        self.api.classic['required_status_checks']['checks'].append(extra)
        with self.assertRaisesRegex(PublicationDenied,'PROTECTION_DRIFT'):self.check()
