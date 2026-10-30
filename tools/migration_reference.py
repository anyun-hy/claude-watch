#!/usr/bin/env python3
"""Whitelisted legacy oracles for migration tests. No live account or OS mutations."""
import json
from pathlib import Path
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "monitor/Resources"))
from watch_switcher import automatic_policy, audit, region, stun
from watch_switcher.common import SwitcherError, validate_config
from watch_switcher import common
import importlib.util
import ast
import datetime
import ipaddress
import os
import pathlib
import re
import subprocess
import tempfile
import types
import urllib.error
import urllib.parse
roles_spec=importlib.util.spec_from_file_location("migration_process_roles",ROOT/"monitor/Resources/process_roles.py")
roles=importlib.util.module_from_spec(roles_spec)
roles_spec.loader.exec_module(roles)

def tag_reference():
    """Compile whitelisted definitions, never the adapter's dispatcher or collector."""
    source=(ROOT/"claude-watch.sh").read_text().split("<<'PY_TAG'\n",1)[1].split("\nPY_TAG\n",1)[0]
    names={"yaml_scalar","controller_credentials","resolve_chain","resolve_selection","published_rules","api_snapshot","group_is_direct",
           "epoch_from_start","process_epoch","normalized_dns_host","is_tag_process","inspect_entry","listener_query",
           "dns_listener_matches","source_candidate","record_identity","translated_fakeip_destination",
           "fakeip_destination_matches","destination_evidence","correlate_flow","fakeip_dns_config","query_fakeip_dns","collect_fakeip_evidence"}
    constants={"HOST","PORT","TAG_BINARY_DIR","API_PATHS","RULE_DOMAINS","RULE_TYPES","MAX_RULE_ENTRIES","MAX_RULE_TEXT","FAKE_IP_NETWORK"}
    tree=ast.parse(source)
    nodes=[n for n in tree.body if (isinstance(n,ast.FunctionDef) and n.name in names|{"connection_policy"}) or
           (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in constants for target in n.targets for t in ast.walk(target)))]
    ns={"datetime":datetime,"ipaddress":ipaddress,"json":json,"math":__import__("math"),"os":SimpleNamespace(getuid=lambda:501,path=os.path),"pathlib":pathlib,"re":re,
        "subprocess":subprocess,"urllib":urllib,"time":__import__("time")}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(ROOT/"claude-watch.sh")+":migration-pure-reference","exec"),ns)
    return types.SimpleNamespace(**ns)

def tag_evaluate(operation,case):
    tag=tag_reference()
    try:
        if operation=="tag_scalar":return {"value":tag.yaml_scalar(case["source"])}
        if operation=="tag_controller" or operation=="tag_dns_config":
            with tempfile.TemporaryDirectory(prefix="cw-tag-reference-") as directory:
                path=Path(directory)/"config.yaml";path.write_text(case["source"])
                if operation=="tag_controller":return {"value":tag.controller_credentials(path)}
                port,network=tag.fakeip_dns_config(path);return {"value":[port,str(network)]}
        if operation=="tag_host":return tag.normalized_dns_host(case)
        if operation=="tag_chain":return tag.resolve_chain(case["proxies"],case["group"])
        if operation=="tag_rules":return {"value":tag.published_rules(case)}
        if operation=="tag_epoch":return tag.epoch_from_start(case)
        if operation=="tag_fake_collect":
            with tempfile.TemporaryDirectory(prefix="cw-fakeip-reference-") as directory:
                path=Path(directory)/"config.yaml";path.write_text(case["source"])
                ns=tag.collect_fakeip_evidence.__globals__;elapsed=[0];calls=[];after=[False]
                def command():
                    kernel=case.get("after_kernel",case["kernel"]) if after[0] else case["kernel"]
                    return SimpleNamespace(returncode=kernel["status"],stdout=kernel["stdout"],stderr=kernel["stderr"])
                ns["run_readonly"]=lambda _argv:command();ns["route_interface"]=lambda _address:case.get("interface","utun4")
                def query(host,port,timeout):
                    calls.append(host)
                    if case.get("query_error"):raise ValueError("fixture_timeout")
                    return case.get("answer",["198.18.1.10",1])
                def connections(*_args):
                    after[0]=True;elapsed[0]=case.get("after_query_elapsed",0)
                    if "current_source" in case:path.write_text(case["current_source"])
                    return {"connections":case.get("current_records",case["records"])}
                ns["query_fakeip_dns"]=query;ns["api_get"]=connections;ns["controller_credentials"]=lambda _filename:("http://127.0.0.1:9090","")
                ns["process_table"]=lambda:{int(k):v for k,v in case.get("current_processes",case["processes"]).items()}
                ns["process_epoch"]=lambda _stamp:case["process_start"]
                snapshot=(command(),case["snapshot_at"]) if "snapshot_at" in case else None
                with patch.object(ns["time"],"time",side_effect=lambda:case["now"]+elapsed[0]),patch.object(ns["time"],"monotonic",return_value=0):
                    value=tag.collect_fakeip_evidence(path,case["entry"],case["api"],case["records"],
                        [(s["flow"],s["stamp"],s["valid"]) for s in case["flows"]],{int(k):v for k,v in case["processes"].items()},snapshot)
                return {"proofs":value,"calls":len(calls)}
        if operation=="tag_dns_answer":
            ns=tag.query_fakeip_dns.__globals__
            with patch.object(subprocess,"run",return_value=SimpleNamespace(returncode=case["status"],stdout=case["stdout"],stderr=case["stderr"])):
                return {"value":tag.query_fakeip_dns(case["host"],5353,.2)}
        if operation=="tag_destination":return tag.destination_evidence(case)
        if operation=="tag_inspect":
            def table(rows):return {int(k):v for k,v in rows.items()}
            listener=SimpleNamespace(returncode=case["listener"]["status"],stdout=case["listener"]["stdout"],stderr=case["listener"]["stderr"],listener_source=case["listener"]["source"])
            return tag.inspect_entry(table(case["before"]),table(case["after"]),listener,case["reachable"])
        if operation=="tag_dns_listener":
            kernel=SimpleNamespace(returncode=case["kernel"]["status"],stdout=case["kernel"]["stdout"],stderr=case["kernel"]["stderr"])
            return tag.dns_listener_matches(kernel,case["port"],case["owner"],{int(k):v for k,v in case["processes"].items()})
        if operation=="tag_listener_fallback":
            def command(v):return SimpleNamespace(returncode=v["status"],stdout=v["stdout"],stderr=v["stderr"],args=[])
            ns=tag.listener_query.__globals__;ns["run_readonly"]=lambda _argv:command(case["lsof"])
            result=tag.listener_query(command(case["kernel"]))
            return {"status":result.returncode,"stdout":result.stdout,"stderr":result.stderr,"source":getattr(result,"listener_source","lsof")}
        if operation=="tag_api_snapshot":
            ns=tag.api_snapshot.__globals__;ns["controller_credentials"]=lambda _: ("http://127.0.0.1:9090","")
            def get(_base,_secret,path):
                if path=="/rules" and case.get("rules_error"):raise urllib.error.HTTPError("http://127.0.0.1:9090/rules",case["rules_error"],"fixture",{},None)
                return case[path]
            ns["api_get"]=get
            return tag.api_snapshot("unused",case["group"])
        if operation=="tag_correlate":
            ns=tag.correlate_flow.__globals__;ns["process_epoch"]=lambda _:case.get("process_start")
            ns["route_interface"]=lambda _address:case.get("interface","utun4")
            return tag.correlate_flow(case["flow"],case["stamp"],case["api"],case["records"],case["group"],case["expected_node"],case["now"],case.get("proofs",{}))
    except (ValueError,TypeError) as error:return {"error":str(error)}
    raise ValueError("unsupported_tag_reference_operation")


def evaluate(operation, case):
    if operation == "cli_parse":
        sys.path.insert(0,str(ROOT/"monitor/Resources"))
        import switcher
        try:
            value=vars(switcher.parser().parse_args(case))
            return {"value":{k:str(v) if isinstance(v,Path) else v for k,v in value.items()}}
        except SystemExit:return {"error":"invalid_arguments"}
    if operation.startswith("tag_"):return tag_evaluate(operation,case)
    if operation == "process_tokens":return roles.command_tokens(case["command"],case.get("executable",""))
    if operation == "process_classify":
        specs=[(s["executable"],s["arguments"],s["name"]) for s in case.get("specs",[])]
        with patch.object(roles,"resolve",side_effect=lambda s:s):return roles.classify(case["tokens"],case["executable"],specs)
    if operation == "dns_row":
        return audit.dns_row(case)
    if operation == "reconcile":
        before=case["before"].copy()
        return {"transition":audit.reconcile_observations(before,case["after"]),"before":before}
    if operation == "service_response":
        return {"result":audit.service_response_result(case["service"],case.get("response"),case.get("status")),
                "label":audit.service_access_label(case["service"],case.get("response"),case.get("status"))}
    if operation == "audit":
        zones={k:set(v) for k,v in case.get("zones",{}).items()}
        with patch.object(region,"country_timezones",return_value=zones), \
             patch.object(automatic_policy,"region_reference",side_effect=region.reference), \
             patch.object(audit,"policy_digest",return_value="test-policy"), \
             patch.object(audit,"_time_text",side_effect=lambda v:f"T{float(v):.0f}" if v else "未提供"):
            return audit.evaluate(validate_config(case.get("config",{})),case["local"],case["online"],case.get("history",[]),case["now"])
    if operation in ("dns_record", "webrtc_record", "dns_status", "webrtc_status"):
        paths=SimpleNamespace(base=Path("/not-a-real-data-directory"))
        system=SimpleNamespace(local=lambda _config: case.get("local", {}))
        def read(path, *_args):
            return case.get("last_valid", {}) if path.name=="dns-leak-last-valid.json" else case.get("receipt", {})
        with patch.object(audit,"atomic_json"), patch.object(audit,"operation_lock",return_value=nullcontext()), \
             patch.object(audit,"read_json",side_effect=read), \
             patch.object(common,"load_config",return_value=common.DEFAULT_CONFIG.copy()), \
             patch.object(audit,"load_config",return_value=common.DEFAULT_CONFIG.copy()), \
             patch.object(audit,"_time_text",side_effect=lambda v:f"T{float(v):.0f}"):
            try:
                if operation=="dns_status":return audit.dns_receipt_status(paths,case["context"],launch=case.get("launch",False),now=case["now"])
                if operation=="webrtc_status":return audit.webrtc_receipt_status(paths,case["context"],now=case["now"])
                method=audit.record_dns_leak if operation=="dns_record" else audit.record_webrtc_risk
                return {"value":method(paths,system,case["probe"],expected_context=case.get("expected_context"),now=case["now"])}
            except SwitcherError as error:
                return {"error":error.code}
    if operation == "stun_decode":
        try:
            return {"value":stun.decode(bytes.fromhex(case["packet"]),bytes.fromhex(case["transaction"]))}
        except ValueError as error:
            return {"error":str(error)}
    if operation == "config":
        try:
            return {"value": validate_config(case)}
        except SwitcherError as error:
            return {"error": error.code}
    if operation in ("region", "dates"):
        zones = {k: set(v) for k, v in case.get("zones", {}).items()}
        with patch.object(region, "country_timezones", return_value=zones):
            if operation == "region":
                return region.reference(case.get("trace", {}), case.get("geo", {}))
            local, expected = case.get("local", {}), case.get("expected")
            return {"date": region.date_check(local, expected), "locale": region.locale_check(local, expected),
                    "summary": region.date_summary(local), "expected": region.expected_date_summary(local, expected)}
    if operation == "risks":
        return automatic_policy.extract_risks(case.get("online", {}), case.get("measured", {}))
    if operation == "session_risk":
        receipts = case.get("environment_receipts", [])
        def read(path, *_args):
            index = 0 if path.name == "last-environment-detection.json" else 1
            return receipts[index] if index < len(receipts) else {}
        with patch("time.time", return_value=case["now"]), \
             patch.object(audit, "dns_receipt_status", return_value=case["dns"]), \
             patch.object(audit, "webrtc_receipt_status", return_value=case["webrtc"]), \
             patch.object(automatic_policy, "read_json", side_effect=read):
            paths = SimpleNamespace(base=Path("/not-a-real-data-directory"))
            return automatic_policy.session_risk(paths, case["context_id"], case.get("current_ip"))
    raise ValueError("unsupported_reference_operation")


def main():
    raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("reference_input_too_large")
    request = json.loads(raw)
    result = [evaluate(request["operation"], case) for case in request["cases"]]
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
