"""Synthetic connection tests; never read installed credentials or connect."""
import contextlib
import io
import unittest
from unittest import mock
from codestra_control import lease_interface as cli

BINDING='11111111-1111-4111-8111-111111111111'
PROOF='22222222-2222-4222-8222-222222222222'

class LeaseInterfaceTests(unittest.TestCase):
    def run_cli(self,args):
        connection=mock.MagicMock()
        connection.cursor.return_value.__enter__.return_value.fetchone.return_value=({'state':'ACTIVE'},)
        with mock.patch.object(cli,'verify_code_custody'),mock.patch.object(cli,'connect_protected',return_value=connection) as connect,contextlib.redirect_stdout(io.StringIO()) as output:
            code=cli.main(args)
        return code,connection,connect,output.getvalue()
    def test_default_claim_rolls_back_and_receipt_is_unusable(self):
        code,c,connect,output=self.run_cli(['claim','--binding',BINDING,'--proof',PROOF,'--request-id','synthetic'])
        self.assertEqual(code,0);c.rollback.assert_called_once();c.commit.assert_not_called();c.close.assert_called_once()
        self.assertIn('NONE_DRY_RUN',output);self.assertIn('"usable": false',output)
        connect.assert_called_once_with(cli.DIRECTORY/'lease-builder.dsn')
        self.assertEqual(c.cursor.return_value.__enter__.return_value.execute.call_args.args,('SELECT assignment_leases.claim(%s,%s,%s)',(BINDING,PROOF,'synthetic')))
    def test_explicit_apply_commits_only_requested_lifecycle_operation(self):
        code,c,_,output=self.run_cli(['release','--lease',BINDING,'--epoch','7','--request-id','synthetic','--apply'])
        self.assertEqual(code,0);c.commit.assert_called_once();c.rollback.assert_not_called();self.assertIn('"certified": false',output)
    def test_operator_credential_is_separate(self):
        code,_,connect,_=self.run_cli(['revoke','--binding',BINDING,'--reason','synthetic','--request-id','synthetic'])
        self.assertEqual(code,0);connect.assert_called_once_with(cli.DIRECTORY/'lease-operator.dsn')
    def test_invalid_identity_and_fence_do_not_connect(self):
        for args in (['claim','--binding','owner-string','--proof',PROOF,'--request-id','x'],['check','--lease',BINDING,'--epoch','0']):
            code,_,connect,output=self.run_cli(args)
            self.assertEqual(code,1);connect.assert_not_called();self.assertEqual(output.strip(),'LEASE_OPERATION_UNAVAILABLE')
    def test_no_environment_dsn_fallback_or_unverified_transport(self):
        import psycopg2
        for dsn in ('dbname=fixture user=builder','host=fixture dbname=fixture user=builder sslmode=require sslrootcert=/fixture/ca','host=/tmp dbname=fixture user=builder sslmode=verify-full sslrootcert=/fixture/ca'):
            with mock.patch.object(cli,'protected_read',return_value=dsn.encode()),mock.patch.object(psycopg2,'connect') as connect:
                with self.assertRaises(ValueError):cli.connect_protected('/fixture/fixed.dsn')
                connect.assert_not_called()
    def test_verifier_observes_server_description_then_attests(self):
        c=mock.MagicMock();cur=c.cursor.return_value.__enter__.return_value
        description={'binding':{'server':'trusted'},'dependencies':{}};cur.fetchone.side_effect=[(description,),({'proof_id':PROOF},)]
        with mock.patch.object(cli,'GitMaterializer') as materializer:
            materializer.return_value.inspect.return_value={'observed':'actual'}
            result=cli.attest_materialization(c,BINDING,object())
            materializer.return_value.inspect.assert_called_once_with(description)
        self.assertEqual(result,{'proof_id':PROOF});c.commit.assert_called_once()
        self.assertEqual(cur.execute.call_args_list[0].args,('SELECT assignment_leases.describe(%s)',(BINDING,)))
        self.assertEqual(cur.execute.call_args_list[1].args[0],'SELECT assignment_leases.attest(%s,%s)')
    def test_database_failure_rolls_back_and_hides_error_values(self):
        c=mock.MagicMock();c.cursor.side_effect=RuntimeError('synthetic-secret')
        with mock.patch.object(cli,'verify_code_custody'),mock.patch.object(cli,'connect_protected',return_value=c),contextlib.redirect_stdout(io.StringIO()) as output:
            code=cli.main(['check','--lease',BINDING,'--epoch','1','--apply'])
        self.assertEqual(code,1);c.rollback.assert_called_once();c.close.assert_called_once();self.assertNotIn('synthetic-secret',output.getvalue())
