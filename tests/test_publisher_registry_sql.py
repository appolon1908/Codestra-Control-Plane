"""Disposable socket-only SQL contract checks; never uses an installed DSN."""
from pathlib import Path
import unittest
import test_scoped_registration as cluster
from codestra_control.publisher_acquisition import RestrictedRegistry
from codestra_control.publisher_adapter import PublicationDenied
import test_decision as fixture

@unittest.skipUnless((cluster.PG/'initdb').exists(),'PostgreSQL16 fixture required')
class PublisherRegistrySQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cluster.ScopedRegistrationTests.setUpClass()
        try:
            with cluster.ScopedRegistrationTests.connect('fixture_admin') as c,c.cursor() as cur:
                cur.execute((Path(__file__).resolve().parents[1]/'006-publisher-authority-read-model.sql').read_text())
                cur.execute('GRANT USAGE ON SCHEMA publisher_authority TO alice; GRANT SELECT ON publisher_authority.bindings TO alice')
        except BaseException:
            cluster.ScopedRegistrationTests.tearDownClass();raise
    @classmethod
    def tearDownClass(cls):cluster.ScopedRegistrationTests.tearDownClass()
    def test_runtime_can_read_but_cannot_write_or_create_authority(self):
        c=cluster.ScopedRegistrationTests.connect('alice');self.addCleanup(c.close)
        with c,c.cursor() as cur:
            cur.execute('SELECT count(*) FROM publisher_authority.bindings');self.assertEqual(cur.fetchone(),(0,))
            cur.execute("SELECT has_schema_privilege(session_user,'publisher_authority','CREATE'),has_table_privilege(session_user,'publisher_authority.bindings','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')")
            self.assertEqual(cur.fetchone(),(False,False))
    def test_socket_trust_fixture_cannot_be_mistaken_for_authenticated_tls_session(self):
        c=cluster.ScopedRegistrationTests.connect('alice');self.addCleanup(c.close)
        with self.assertRaisesRegex(PublicationDenied,'VERIFIED_DATABASE_TLS_REQUIRED'):
            RestrictedRegistry(c).acquire(fixture.REQUEST)
