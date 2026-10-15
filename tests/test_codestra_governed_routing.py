"""Declared Codestra section aliases; synthetic boundaries confer no authority."""
import contextlib
import io
import sys
import unittest
from unittest import mock
from test_registered_promotion_routes import Database, SHA
import test_registered_promotion_routes as route_fixtures

SECTIONS = (
    ("01-core", "workstation/ws01-core"), ("02-api", "workstation/ws02-api"),
    ("03-security", "workstation/ws03-security"), ("04-deployment", "workstation/ws04-deployment"),
    ("05-observability", "workstation/ws05-observability"), ("06-testing", "workstation/ws06-testing"),
    ("07-saas", "workstation/ws07-saas"), ("08-release", "workstation/ws08-release"),
)

class CodestraGovernedRoutingTests(unittest.TestCase):
    def setUp(self):
        self.probe = route_fixtures.RegisteredPromotionRouteTests()
        self.addCleanup(self.probe.doCleanups)
        self.probe.setUp()

    def database(self, section="06-testing", parent="workstation/ws06-testing"):
        db = Database()
        db.product["repository"] = "appolon1908/codestra"
        db.workstation.update(branch=f"subsection/{section}--01-baseline", parent_branch=parent)
        db.section.update(branch=parent, section_key=section)
        return db

    def github(self, head, base, db, product="codestra", observed=SHA):
        driver = self.probe.driver
        driver.connect.side_effect = None
        driver.connect.return_value = db
        main = self.probe.github["main"]
        argv = ["codestra-github-check", "--product", product, "--repo-path", "/unused",
                "--head-ref", head, "--base-ref", base, "--head-sha", SHA]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.dict(main.__globals__, {"remote_sha": lambda *_: observed}):
            return main() == 0

    def publisher(self, head, base, db, product="codestra", observed=SHA):
        validate = self.probe.publisher["validate"]
        with mock.patch.dict(validate.__globals__, {"remote_sha": lambda *_: observed}):
            return validate(db, product, db.product["test_branch"], "/unused", head, base, SHA)[0]

    def promotion(self, head, base, db, product="codestra", observed=SHA):
        driver = self.probe.driver
        driver.connect.side_effect = None
        driver.connect.return_value = db
        source_level, target_level = (("subsection", "section") if head.startswith("subsection/")
                                      else ("section", "development"))
        main = self.probe.promotion["main"]
        argv = ["codestra-promotion-check", "--product", product, "--source-level", source_level,
                "--source-ref", head, "--target-level", target_level, "--target-ref", base, "--sha", SHA]
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.dict(main.__globals__, {"post_github_status": lambda *_: True}):
            try:
                main()
            except SystemExit as exc:
                return exc.code == 0
        return True

    def implementations(self):
        return self.github, self.publisher, self.promotion

    def test_declared_subsections_route_to_their_registered_workstation_sections(self):
        for section, parent in SECTIONS:
            for impl in self.implementations():
                with self.subTest(section=section, entrypoint=impl.__name__):
                    self.assertTrue(impl(f"subsection/{section}--01-baseline", parent, self.database(section,parent)))

    def test_declared_workstation_sections_route_only_to_development(self):
        for section, parent in SECTIONS:
            for impl in self.implementations():
                with self.subTest(section=section, entrypoint=impl.__name__):
                    self.assertTrue(impl(parent,"development",self.database(section,parent)))

    def test_aliases_do_not_apply_to_other_products(self):
        for product in ("Middleware-","backend2","Codestra-Control-Plane"):
            for impl in self.implementations():
                self.assertFalse(impl("workstation/ws06-testing","development",self.database(),product=product))

    def test_governance_and_hotfix_shortcuts_remain_rejected(self):
        for head,base in (("governance/dedicated-exact-sha-ci","development"),
                          ("hotfix/public-ux-api-20261008","production"),
                          ("workstation/ws06-testing","production"),
                          ("subsection/06-testing--01-baseline","development")):
            for impl in self.implementations():
                self.assertFalse(impl(head,base,self.database()))

    def test_unlisted_workstation_names_do_not_become_sections(self):
        for head in ("workstation/dev-desktop","workstation/governance-control-plane",
                     "workstation/ws09-other","workstation/ws06-security","workstation/arbitrary"):
            for impl in self.implementations():
                self.assertFalse(impl(head,"development",self.database()))

    def test_subsection_cannot_cross_to_another_declared_section(self):
        for impl in self.implementations():
            self.assertFalse(impl("subsection/06-testing--01-baseline","workstation/ws03-security",
                                  self.database(parent="workstation/ws03-security")))

    def test_exact_parent_registration_is_still_required(self):
        for impl in self.implementations():
            for parent in ("section/06-testing","workstation/ws03-security"):
                self.assertFalse(impl("subsection/06-testing--01-baseline","workstation/ws06-testing",
                                      self.database(parent=parent)))

    def test_missing_registered_subsection_or_section_still_denies(self):
        for impl in self.implementations():
            db=self.database(); db.workstation=None
            self.assertFalse(impl("subsection/06-testing--01-baseline","workstation/ws06-testing",db))
            db=self.database(); db.section=None
            self.assertFalse(impl("workstation/ws06-testing","development",db))

    def test_missing_or_wrong_exact_sha_certificates_still_deny(self):
        for impl in self.implementations():
            for field,value in (("status","COMPLETE"),("exact_sha_certified","b"*40)):
                db=self.database(); db.workstation[field]=value
                self.assertFalse(impl("subsection/06-testing--01-baseline","workstation/ws06-testing",db))
            db=self.database(); db.certificate=None; db.section["status"]="NOT_STARTED"
            self.assertFalse(impl("workstation/ws06-testing","development",db))

    def test_modern_registered_section_names_continue_to_work(self):
        for impl in self.implementations():
            db=self.database(parent="section/06-testing")
            self.assertTrue(impl("subsection/06-testing--01-baseline","section/06-testing",db))
            self.assertTrue(impl("section/06-testing","development",db))

    def test_online_head_sha_mismatch_still_denies_alias_routes(self):
        for impl in (self.github,self.publisher):
            self.assertFalse(impl("workstation/ws06-testing","development",self.database(),observed="b"*40))

    def test_workstation_refs_cannot_be_registered_as_environment_aliases(self):
        resolver=self.probe.github["promotion_levels"]
        for ref in ("workstation/ws06-testing","workstation/arbitrary","subworkstation/anything"):
            self.assertIsNone(resolver("development",ref,ref))

    def test_incomplete_subsection_aliases_are_not_admitted(self):
        for head in ("subsection/06-testing", "subsection/06-testing--"):
            for impl in self.implementations():
                db = self.database()
                db.workstation["branch"] = head
                self.assertFalse(impl(head, "workstation/ws06-testing", db))

    def test_alias_classification_requires_the_explicit_product(self):
        resolver = self.probe.github["promotion_levels"]
        self.assertIsNone(resolver("workstation/ws06-testing", "development", "testing"))
