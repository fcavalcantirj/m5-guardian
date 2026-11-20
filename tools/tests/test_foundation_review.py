import importlib.util,os,unittest
from pathlib import Path
ROOT=Path(os.environ.get('GUARDIAN_TEST_ROOT',str(Path(__file__).resolve().parents[2])))
spec=importlib.util.spec_from_file_location('review',ROOT/'tools/review-with-claude.py');review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)
class ReviewTests(unittest.TestCase):
 def test_foundation_carries_code_tests_and_evidence(self):
  files=review.input_files('foundation')
  for rel in ['firmware/components/guardian_core/parser.cpp','firmware/components/guardian_core/core.cpp','firmware/components/guardian_presenter/presenter.cpp','firmware/tests/parser_check.cpp','lab/live/run.py','docs/L02-live-validation.md','docs/G09-validation.md']:
   self.assertIn(rel,files)
  self.assertNotIn('guardian-tasks.json',files) # foundation implementation review, not another whole ledger debate
  self.assertEqual(len(files),len(set(files)))
 def test_ledger_mode_kept(self):self.assertEqual(review.input_files('ledger'),review.FILES)
 def test_scope_verdict_checked(self):
  data={'modelUsage':{review.MODEL:{}},'result':'Detailed findings\nAPPROVE FOUNDATION'}
  self.assertEqual(review.classify_response(data,0,'foundation')['outcome'],'review_received')
  self.assertEqual(review.classify_response(data,0,'ledger')['outcome'],'incomplete_review')
 def test_refusal_model_and_transport_never_pass(self):
  for data,rc in [({'modelUsage':{review.MODEL:{}},'result':'APPROVE FOUNDATION','stop_reason':'refusal'},0),({'modelUsage':{'other':{}},'result':'APPROVE FOUNDATION'},0),({'modelUsage':{review.MODEL:{}},'result':'APPROVE FOUNDATION'},1)]:
   self.assertFalse(review.classify_response(data,rc,'foundation')['response_complete_requested_model'])
 def test_explicit_opus_override_verified_exactly(self):
  data={'modelUsage':{'claude-opus-5-5':{}},'result':'Review findings\nAPPROVE FOUNDATION'}
  self.assertEqual(review.classify_response(data,0,'foundation','claude-opus-5-5')['outcome'],'review_received')
  self.assertFalse(review.classify_response(data,0,'foundation')['requested_model_verified'])
 def test_model_override_does_not_rewrite_source_evidence(self):
  original='Original policy requests '+review.MODEL
  prompt=review.review_prompt('foundation',{'policy.md':original},'claude-opus-5-5')
  self.assertTrue(prompt.endswith(original))
class IntegratedReviewTests(unittest.TestCase):
 """G22: the final integrated review (ledger pin: claude-fable-5-2, high effort, no tools)."""
 def test_integrated_carries_product_source_ledger_and_device_evidence(self):
  files=review.input_files('integrated')
  for rel in ['guardian-tasks.json','README.md','firmware/README.md','docs/attack-coverage.md','THIRD_PARTY_NOTICES.md',
              'firmware/components/guardian_core/threats.cpp','firmware/components/guardian_core/datapath.cpp',
              'firmware/components/guardian_core/ble.cpp','firmware/components/guardian_core/include/guardian/threats.hpp',
              'firmware/components/guardian_presenter/presenter.cpp','firmware/adapters/setup/setup.cpp',
              'firmware/adapters/ota/ota.cpp','firmware/adapters/tune/session.cpp','firmware/adapters/measurement/measurement.cpp',
              'firmware/adapters/companion/screens.cpp','firmware/boards/sticks3/main/measurement_main.cpp',
              'firmware/boards/sticks3/main/ota_board.cpp','firmware/evidence/sticks3-G16T-20261119.log']:
   self.assertIn(rel,files)
  self.assertEqual(len(files),len(set(files)))
  for rel in files:self.assertTrue((ROOT/rel).is_file(),rel)
 def test_integrated_withholds_own_review_blob_and_tests(self):
  files=review.input_files('integrated')
  self.assertNotIn('docs/review-status.md',files)   # the reviewer is not handed the worker's conclusions
  self.assertNotIn('firmware/adapters/imu/bmi270_config.cpp',files)   # an 8 kB vendor blob, not reviewable text
  self.assertFalse([f for f in files if f.startswith('firmware/tests/')])   # named in the prompt as omitted
 def test_integrated_defaults_to_the_ledger_pin(self):
  self.assertEqual(review.default_model('integrated'),'claude-fable-5-2')
  self.assertEqual(review.default_model('ledger'),review.MODEL)
  self.assertEqual(review.default_model('foundation'),review.MODEL)
 def test_integrated_prompt_names_model_scope_and_omissions(self):
  prompt=review.review_prompt('integrated',{'a.md':'body of a'},'claude-fable-5-2')
  self.assertIn('claude-fable-5-2',prompt);self.assertNotIn('claude-fable-5-1',prompt)
  self.assertIn('APPROVE INTEGRATED',prompt);self.assertIn('REVISE INTEGRATED',prompt)
  self.assertIn('test sources are not supplied',prompt)
  self.assertTrue(prompt.endswith('body of a'))
 def test_integrated_verdict_and_model_checked(self):
  good={'modelUsage':{'claude-fable-5-2':{}},'result':'Findings\nREVISE INTEGRATED'}
  self.assertEqual(review.classify_response(good,0,'integrated','claude-fable-5-2')['outcome'],'review_received')
  self.assertEqual(review.classify_response(good,0,'integrated')['outcome'],'model_unverified')   # 5-1 was not what answered
  other={'modelUsage':{'claude-fable-5-2':{},'claude-haiku-5-5':{}},'result':'Findings\nREVISE INTEGRATED'}
  self.assertEqual(review.classify_response(other,0,'integrated','claude-fable-5-2')['outcome'],'model_unverified')
  refused={'modelUsage':{'claude-fable-5-2':{}},'result':'REVISE INTEGRATED','stop_reason':'refusal'}
  self.assertEqual(review.classify_response(refused,0,'integrated','claude-fable-5-2')['outcome'],'provider_refused')
 def test_integrated_cli_has_no_tools_and_only_supplied_context(self):
  argv=review.cli_args('/bin/claude','claude-fable-5-2','integrated')
  self.assertEqual(argv[:2],['/bin/claude','-p'])
  for flag,value in [('--model','claude-fable-5-2'),('--effort','high'),('--tools',''),('--setting-sources','project'),('--output-format','stream-json')]:
   self.assertEqual(argv[argv.index(flag)+1],value)
  for flag in ['--strict-mcp-config','--no-session-persistence','--disable-slash-commands','--verbose']:self.assertIn(flag,argv)
  self.assertNotIn('--fallback-model',argv)
  legacy=review.cli_args('/bin/claude',review.MODEL,'foundation')
  self.assertEqual(legacy[legacy.index('--output-format')+1],'json');self.assertNotIn('--setting-sources',legacy)
 def test_stream_result_and_session_facts(self):
  lines=['{"type":"system","subtype":"init","model":"claude-fable-5-2","tools":[],"mcp_servers":[],"claude_code_version":"9.9"}',
         '{"type":"assistant","message":{}}','not json','{"type":"result","result":"x\\nAPPROVE INTEGRATED","modelUsage":{"claude-fable-5-2":{}}}']
  response,facts=review.read_stream('\n'.join(lines))
  self.assertEqual(response['result'],'x\nAPPROVE INTEGRATED')
  self.assertEqual(facts,{'model':'claude-fable-5-2','tools':[],'mcp_servers':[],'claude_code_version':'9.9'})
  self.assertEqual(review.read_stream('{"type":"system","subtype":"init","model":"m"}'),(None,{'model':'m'}))
 def test_child_environment_is_a_plain_terminal(self):
  env=review.child_env({'PATH':'/bin','HOME':'/h','CLAUDE_MODEL':'x','CLAUDE_EFFORT':'low','CLAUDECODE':'1','CLAUDE_CODE_SESSION_ID':'s','ANTHROPIC_MODEL':'y'})
  self.assertEqual(env,{'PATH':'/bin','HOME':'/h'})
  absent={'GUARDIAN_LOCAL_CONF':'/nonexistent/local.conf'}
  with self.assertRaises(ValueError):review.child_env(dict(absent,CLAUDE_CONFIG_DIR='/tmp/x/.claude-work-profile',GUARDIAN_FORBIDDEN_CLAUDE_CONFIG='work-profile'))
  self.assertNotIn('CLAUDE_CONFIG_DIR',review.child_env(dict(absent,CLAUDE_CONFIG_DIR='/tmp/x/.claude-work-profile')))
if __name__=='__main__':unittest.main()
