"""Acceptance checks over real C++ output and independent RF witness records.

These are scenario expectations, not a substitute detector or product grade.
"""
def assess(scenario,states,witness,emitter,ack_us,end_us,uncertainty_us,groups,association_baseline=0,ap_stop_observed=False,post_stop_listening=False):
    fresh=[s for s in states if s.get('origin')=='live' and s.get('has_security') and s.get('coverage')==1 and s.get('age_ms',999999)<=1000]
    enough=len(fresh)>=5 and fresh[-1]['now_ms']-fresh[0]['now_ms']>=5000 if fresh else False
    bursts=[s for s in states if s.get('burst')]
    latency=None
    if len(witness.times)>=20 and bursts and bursts[0].get('burst_acquired_ms',0):latency=bursts[0]['now_ms']-bursts[0]['burst_acquired_ms']
    stop_observed=witness.stop_proven(ack_us,end_us,uncertainty_us,emitter.get('submitted_groups',emitter.get('completed_groups',0)) if emitter else 0,post_stop_listening)
    result={'fresh_states':len(fresh),'fresh_span_ms':fresh[-1]['now_ms']-fresh[0]['now_ms'] if fresh else 0,'threshold_to_report_ms':latency,'latency_budget_ms':1500,'on_air_stop_observed':stop_observed}
    ok=enough
    if scenario in ('quiet','reconnect'):ok=ok and not any(s.get('burst') or s.get('unexpected_ap') or s.get('settings_changed') for s in states)
    elif scenario in ('burst','recovery'):
        ok=ok and bool(emitter) and any(s.get('incident_visible') for s in bursts) and stop_observed and latency is not None and 0<=latency<=1500
        if scenario=='recovery':ok=ok and bool(fresh) and not fresh[-1].get('burst') and bool(bursts) and fresh[-1]['now_ms']-bursts[0]['now_ms']>=60000 and states[-1]['now_ms']-fresh[-1]['now_ms']<2000
    elif scenario in ('stop','stop-inflight'):ok=ok and stop_observed and bool(emitter) and emitter.get('stop_requested') and emitter.get('completed_groups',groups)<groups
    elif scenario=='drop':
        degraded=[s for s in states if s.get('coverage')==3 and s.get('mood')==0 and s.get('coverage_drops',0)>0]
        ok=ok and bool(degraded) and bool(fresh) and fresh[-1]['now_ms']>degraded[-1]['now_ms'] and not any(s.get('burst') for s in states)
    elif scenario=='stale':ok=ok and bool(states) and states[-1].get('mood')==0 and states[-1].get('coverage')!=1 and states[-1].get('age_ms',0)>=30000
    elif scenario=='settings':
        modes=[]
        for s in fresh:
            mode=s.get('mode',0)
            if not modes or modes[-1]!=mode:modes.append(mode)
        result['advertised_mode_sequence']=modes
        ok=ok and modes==[4,5,4] and any(s.get('mode')==5 and s.get('pmf')==3 for s in fresh) and any(s.get('settings_changed') for s in states) and not any(s.get('alert') and s.get('settings_changed') for s in states) and ap_stop_observed and bool(emitter) and emitter.get('role')=='test_ap'   # G25: a security change is amber (recorded, never the red ALERT at the default sensitivity)
    elif scenario=='channel':
        channels=[]
        for s in fresh:
            channel=s.get('channel',0)
            if not channels or channels[-1]!=channel:channels.append(channel)
        gaps=[];previous=None
        for s in fresh:
            if previous is not None and s.get('channel')!=previous.get('channel'):
                gaps.append(any(previous['now_ms']<g['now_ms']<s['now_ms'] and g.get('coverage')!=1 and g.get('mood')==0 for g in states))
            previous=s
        gap=len(gaps)==2 and all(gaps)
        result['observed_channel_sequence']=channels;result['coverage_gap_visible']=gap
        result['transition_gaps']=gaps
        ok=ok and channels==[13,6,13] and gap and not any(s.get('settings_changed') or s.get('alert') for s in states) and ap_stop_observed   # G25: the router moving channel is followed silently, never an incident and bool(emitter) and emitter.get('role')=='test_ap'
    elif scenario in ('related-approved','related-unapproved'):
        observed=max((s.get('watched_advertisements',0) for s in states),default=0)
        unexpected=any(s.get('unexpected_ap') and s.get('incident_visible') for s in states)
        result['watched_advertisements']=observed
        ok=ok and observed>=20 and ap_stop_observed and bool(emitter) and emitter.get('role')=='test_ap' and unexpected==(scenario=='related-unapproved') and not any(s.get('burst') or s.get('settings_changed') for s in states)
    else:ok=False
    if scenario=='stop-inflight':ok=ok and emitter.get('interrupted_inflight',False) and 0<witness.count<3
    if scenario=='reconnect':
        result['association_frames_after_baseline']=states[-1].get('association_frames',0)-association_baseline if states else 0
        ok=ok and result['association_frames_after_baseline']>0
    result['pass']=bool(ok);return result
