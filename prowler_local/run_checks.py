"""
run_checks.py — Runs all 608 Prowler AWS checks using embedded source.
"""
import sys
import os
import importlib
import glob
import csv
import json
import uuid
import traceback
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import boto3

# ── Path setup ─────────────────────────────────────────────────────────────────
PROWLER_DIR = os.path.join(os.path.dirname(__file__), "prowler_src")
sys.path.insert(0, PROWLER_DIR)
sys.path.insert(0, os.path.dirname(__file__))

# ── Import shim ────────────────────────────────────────────────────────────────
from prowler_shim import MinimalAwsProvider

# ── CSV columns (Prowler-compatible) ──────────────────────────────────────────
CSV_COLUMNS = [
    "AUTH_METHOD","TIMESTAMP","ACCOUNT_UID","ACCOUNT_NAME","ACCOUNT_EMAIL",
    "ACCOUNT_ORGANIZATION_UID","ACCOUNT_ORGANIZATION_NAME","ACCOUNT_TAGS",
    "FINDING_UID","PROVIDER","CHECK_ID","CHECK_TITLE","CHECK_TYPE",
    "STATUS","STATUS_EXTENDED","MUTED","SERVICE_NAME","SUBSERVICE_NAME",
    "SEVERITY","RESOURCE_TYPE","RESOURCE_UID","RESOURCE_NAME","RESOURCE_DETAILS",
    "RESOURCE_TAGS","PARTITION","REGION","DESCRIPTION","RISK","RELATED_URL",
    "REMEDIATION_RECOMMENDATION_TEXT","REMEDIATION_RECOMMENDATION_URL",
    "REMEDIATION_CODE_NATIVEIAC","REMEDIATION_CODE_TERRAFORM",
    "REMEDIATION_CODE_CLI","REMEDIATION_CODE_OTHER",
    "COMPLIANCE","CATEGORIES","DEPENDS_ON","RELATED_TO","NOTES",
]


def discover_checks(services_filter: Optional[List[str]] = None) -> List[Dict]:
    """Discover all check modules from embedded prowler source."""
    base = os.path.join(PROWLER_DIR, "prowler", "providers", "aws", "services")
    checks = []

    for meta_path in sorted(glob.glob(f"{base}/**/*.metadata.json", recursive=True)):
        parts = meta_path.split(os.sep)
        # structure: .../services/SERVICE/CHECK_NAME/CHECK_NAME.metadata.json
        service_name = parts[-3]
        check_name   = parts[-2]

        if services_filter and service_name not in services_filter:
            continue

        # Find the check Python file
        check_py = os.path.join(os.path.dirname(meta_path), f"{check_name}.py")
        if not os.path.exists(check_py):
            continue

        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except Exception:
            continue

        checks.append({
            "check_id":    check_name,
            "service":     service_name,
            "meta_path":   meta_path,
            "check_py":    check_py,
            "metadata":    meta,
        })

    return checks


def load_check_class(check_info: Dict):
    """Dynamically import a Prowler check class."""
    service  = check_info["service"]
    check_id = check_info["check_id"]

    module_path = (
        f"prowler.providers.aws.services.{service}.{check_id}.{check_id}"
    )
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, check_id)
        return cls
    except Exception as e:
        return None


def load_service_client(service: str, provider: MinimalAwsProvider):
    """Load a Prowler service client (the singleton that pre-fetches data)."""
    module_path = f"prowler.providers.aws.services.{service}.{service}_client"
    try:
        # We need to set the client module's global variable
        # Prowler uses module-level singletons
        svc_module_path = f"prowler.providers.aws.services.{service}.{service}_service"
        svc_mod  = importlib.import_module(svc_module_path)
        # Get the service class (named same as service, capitalized)
        svc_class_name = service.upper() if service == "iam" else service.capitalize()
        # Try various capitalizations
        svc_class = None
        for name in [service.upper(), service.capitalize(),
                     service.replace("awslambda","Lambda").capitalize(),
                     "".join(w.capitalize() for w in service.split("_"))]:
            svc_class = getattr(svc_mod, name, None)
            if svc_class:
                break
        if not svc_class:
            # Try getting any class that subclasses AWSService
            for attr in dir(svc_mod):
                obj = getattr(svc_mod, attr)
                try:
                    if (isinstance(obj, type) and
                        hasattr(obj, '__mro__') and
                        any(c.__name__ == 'AWSService' for c in obj.__mro__[1:])):
                        svc_class = obj
                        break
                except Exception:
                    pass

        if not svc_class:
            return None

        instance = svc_class(provider)

        # Now set the client module's singleton
        client_mod = importlib.import_module(module_path)
        # The client module typically has: service_client = SERVICE(provider)
        # We override that with our instance
        client_attr = f"{service}_client"
        setattr(client_mod, client_attr, instance)
        return instance

    except Exception as e:
        return None


def finding_to_csv_row(finding, meta: dict, account_id: str,
                        account_name: str) -> dict:
    """Convert a Prowler Check_Report_AWS to a CSV row."""
    try:
        status   = finding.status if hasattr(finding, "status") else "MANUAL"
        extended = getattr(finding, "status_extended", "")
        region   = getattr(finding, "region", "global") or "global"
        res_uid  = getattr(finding, "resource_uid",  "")
        res_name = getattr(finding, "resource_name", "")
        res_id   = getattr(finding, "resource_id",   "")
        res_arn  = getattr(finding, "resource_arn",  "")

        # Prowler sometimes uses resource_id instead of resource_uid
        if not res_uid:
            res_uid = res_arn or res_id

        if not res_name:
            res_name = res_id

        rem  = meta.get("Remediation", {})
        code = rem.get("Code", {})

        return {
            "AUTH_METHOD":                     "profile",
            "TIMESTAMP":                       datetime.now(timezone.utc).isoformat(),
            "ACCOUNT_UID":                     account_id,
            "ACCOUNT_NAME":                    account_name,
            "ACCOUNT_EMAIL":                   "",
            "ACCOUNT_ORGANIZATION_UID":        "",
            "ACCOUNT_ORGANIZATION_NAME":       "",
            "ACCOUNT_TAGS":                    "",
            "FINDING_UID":                     str(uuid.uuid4()),
            "PROVIDER":                        "aws",
            "CHECK_ID":                        meta.get("CheckID",""),
            "CHECK_TITLE":                     meta.get("CheckTitle",""),
            "CHECK_TYPE":                      "|".join(meta.get("CheckType",[])),
            "STATUS":                          str(status),
            "STATUS_EXTENDED":                 str(extended),
            "MUTED":                           "False",
            "SERVICE_NAME":                    meta.get("ServiceName",""),
            "SUBSERVICE_NAME":                 meta.get("SubServiceName",""),
            "SEVERITY":                        meta.get("Severity","medium"),
            "RESOURCE_TYPE":                   meta.get("ResourceType",""),
            "RESOURCE_UID":                    str(res_uid),
            "RESOURCE_NAME":                   str(res_name),
            "RESOURCE_DETAILS":                getattr(finding,"resource_details",""),
            "RESOURCE_TAGS":                   "",
            "PARTITION":                       "aws",
            "REGION":                          str(region),
            "DESCRIPTION":                     meta.get("Description",""),
            "RISK":                            meta.get("Risk",""),
            "RELATED_URL":                     meta.get("RelatedUrl",""),
            "REMEDIATION_RECOMMENDATION_TEXT": rem.get("Recommendation",{}).get("Text",""),
            "REMEDIATION_RECOMMENDATION_URL":  rem.get("Recommendation",{}).get("Url",""),
            "REMEDIATION_CODE_NATIVEIAC":      code.get("NativeIaC",""),
            "REMEDIATION_CODE_TERRAFORM":      code.get("Terraform",""),
            "REMEDIATION_CODE_CLI":            code.get("CLI",""),
            "REMEDIATION_CODE_OTHER":          code.get("Other",""),
            "COMPLIANCE":                      "",
            "CATEGORIES":                      "|".join(meta.get("Categories",[])),
            "DEPENDS_ON":                      "|".join(meta.get("DependsOn",[])),
            "RELATED_TO":                      "|".join(meta.get("RelatedTo",[])),
            "NOTES":                           meta.get("Notes",""),
        }
    except Exception as e:
        return {col: "" for col in CSV_COLUMNS}


def run_account(
    account_id:   str,
    account_name: str,
    profile:      Optional[str],
    regions:      List[str],
    services:     Optional[List[str]] = None,
    skip_checks:  List[str] = None,
    log_fn = print,
) -> List[dict]:
    """Run all Prowler checks for one account. Returns list of CSV row dicts."""
    skip_checks = skip_checks or []

    # Build boto3 session
    session = (boto3.Session(profile_name=profile, region_name=regions[0])
               if profile else boto3.Session(region_name=regions[0]))

    # Resolve real account ID if not provided
    if not account_id or account_id == "unknown":
        try:
            account_id = session.client("sts").get_caller_identity()["Account"]
        except Exception:
            pass

    provider = MinimalAwsProvider(
        boto3_session=session,
        account_id=account_id,
        account_name=account_name,
        regions=regions,
        checks=[],
    )

    checks = discover_checks(services_filter=services)
    log_fn(f"    {len(checks)} checks to run for {account_name}")

    rows = []
    loaded_clients: Dict[str, Any] = {}

    for i, check_info in enumerate(checks):
        check_id = check_info["check_id"]
        service  = check_info["service"]
        meta     = check_info["metadata"]

        if check_id in skip_checks:
            continue

        if (i + 1) % 50 == 0:
            log_fn(f"    [{i+1}/{len(checks)}] running checks...")

        # Load service client once per service
        if service not in loaded_clients:
            loaded_clients[service] = load_service_client(service, provider)

        # Load and instantiate the check class
        check_cls = load_check_class(check_info)
        if not check_cls:
            rows.append({
                **{col: "" for col in CSV_COLUMNS},
                "ACCOUNT_UID":    account_id,
                "ACCOUNT_NAME":   account_name,
                "CHECK_ID":       check_id,
                "CHECK_TITLE":    meta.get("CheckTitle",""),
                "SERVICE_NAME":   service,
                "SEVERITY":       meta.get("Severity","medium"),
                "STATUS":         "MANUAL",
                "STATUS_EXTENDED":"Check class could not be loaded",
                "PROVIDER":       "aws",
                "REGION":         regions[0],
                "DESCRIPTION":    meta.get("Description",""),
                "RISK":           meta.get("Risk",""),
                "CATEGORIES":     "|".join(meta.get("Categories",[])),
                "FINDING_UID":    str(uuid.uuid4()),
                "TIMESTAMP":      datetime.now(timezone.utc).isoformat(),
                "AUTH_METHOD":    "profile",
                "PARTITION":      "aws",
            })
            continue

        # Run the check
        try:
            check_instance = check_cls()
            findings = check_instance.execute()
            if not isinstance(findings, list):
                findings = [findings] if findings else []

            for finding in findings:
                rows.append(finding_to_csv_row(finding, meta, account_id, account_name))

            if not findings:
                # No findings = service has no resources to check
                rows.append({
                    **{col: "" for col in CSV_COLUMNS},
                    "ACCOUNT_UID":    account_id,
                    "ACCOUNT_NAME":   account_name,
                    "CHECK_ID":       check_id,
                    "CHECK_TITLE":    meta.get("CheckTitle",""),
                    "SERVICE_NAME":   service,
                    "SEVERITY":       meta.get("Severity","medium"),
                    "STATUS":         "PASS",
                    "STATUS_EXTENDED":"No resources found for this check",
                    "PROVIDER":       "aws",
                    "REGION":         regions[0],
                    "DESCRIPTION":    meta.get("Description",""),
                    "RISK":           meta.get("Risk",""),
                    "CATEGORIES":     "|".join(meta.get("Categories",[])),
                    "FINDING_UID":    str(uuid.uuid4()),
                    "TIMESTAMP":      datetime.now(timezone.utc).isoformat(),
                    "AUTH_METHOD":    "profile",
                    "PARTITION":      "aws",
                })

        except Exception as e:
            rows.append({
                **{col: "" for col in CSV_COLUMNS},
                "ACCOUNT_UID":    account_id,
                "ACCOUNT_NAME":   account_name,
                "CHECK_ID":       check_id,
                "CHECK_TITLE":    meta.get("CheckTitle",""),
                "SERVICE_NAME":   service,
                "SEVERITY":       meta.get("Severity","medium"),
                "STATUS":         "MANUAL",
                "STATUS_EXTENDED":f"Error: {str(e)[:200]}",
                "PROVIDER":       "aws",
                "REGION":         regions[0],
                "DESCRIPTION":    meta.get("Description",""),
                "RISK":           meta.get("Risk",""),
                "CATEGORIES":     "|".join(meta.get("Categories",[])),
                "FINDING_UID":    str(uuid.uuid4()),
                "TIMESTAMP":      datetime.now(timezone.utc).isoformat(),
                "AUTH_METHOD":    "profile",
                "PARTITION":      "aws",
            })

    log_fn(f"    → {len(rows)} findings generated")
    return rows


def save_csv(rows: List[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, delimiter=";",
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
