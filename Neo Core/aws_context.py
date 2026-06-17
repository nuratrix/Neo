"""Environmental context for AWS resources -- the 'within our environment' layer.

This is what turns a generic CVE score into a risk score for YOUR estate:
  - exposure:    is the resource actually reachable from the internet?
  - criticality: how much does the business care about this asset? (from tags)
  - controls:    WAF/EDR/segmentation that reduce real-world exploitability.

Exposure for EC2 is inferred from public IP + security-group ingress. ECR images
and Lambda default to 'internal' unless overridden. Criticality and controls come
from resource tags so asset owners stay the source of truth. All boto3 access is
lazy and best-effort -- missing permissions degrade to 'unknown', never crash.
"""
from __future__ import annotations

from .models import AssetContext

CRITICALITY_TAG_KEYS = ("Criticality", "criticality", "BusinessCriticality")
CONTROLS_TAG_KEY = "CompensatingControls"  # tag value 0.0-1.0


def _criticality_from_tags(tags: dict) -> str:
    for k in CRITICALITY_TAG_KEYS:
        if k in tags:
            return tags[k].strip().lower()
    return "unknown"


def _controls_from_tags(tags: dict) -> float:
    try:
        return float(tags.get(CONTROLS_TAG_KEY, 0.0))
    except (TypeError, ValueError):
        return 0.0


def _ec2_exposure(ec2, instance_id: str) -> tuple[str, dict]:
    """Best-effort: public if it has a public IP AND an SG open to 0.0.0.0/0."""
    try:
        r = ec2.describe_instances(InstanceIds=[instance_id])
        inst = r["Reservations"][0]["Instances"][0]
    except Exception:
        return "unknown", {}
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    has_public_ip = bool(inst.get("PublicIpAddress"))
    if not has_public_ip:
        return "internal", tags

    open_to_world = False
    sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    if sg_ids:
        try:
            sgs = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    if any(rng.get("CidrIp") == "0.0.0.0/0" for rng in perm.get("IpRanges", [])):
                        open_to_world = True
        except Exception:
            pass
    return ("public" if open_to_world else "internal"), tags


def _assume(base_session, account_id: str, role_name: str, this_account: str):
    """Return a session for `account_id`, assuming `role_name` when it differs
    from the account we're already in. Falls back to the base session on failure."""
    import boto3  # lazy
    if not role_name or not account_id or account_id == this_account:
        return base_session
    try:
        creds = base_session.client("sts").assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="project-smith",
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except Exception:
        return base_session  # no access -> exposure stays 'unknown', never crashes


def build_contexts(findings, region: str = "us-east-1", profile: str | None = None,
                   assume_role_name: str | None = None) -> dict:
    """Return {resource_id: AssetContext} for the resources in `findings`.

    For Organization-wide scans (findings span multiple `account_id`s), pass
    `assume_role_name` -- the cross-account role Smith assumes into each member
    account to read EC2 exposure. Single-account scans leave it None.
    """
    import boto3  # lazy
    base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    try:
        this_account = base.client("sts").get_caller_identity()["Account"]
    except Exception:
        this_account = ""

    ec2_clients: dict = {}  # (account_id, region) -> client, built on demand

    def _ec2_for(f):
        key = (f.account_id, f.region or region)
        if key not in ec2_clients:
            sess = _assume(base, f.account_id, assume_role_name, this_account)
            ec2_clients[key] = sess.client("ec2", region_name=f.region or region)
        return ec2_clients[key]

    contexts: dict = {}
    for f in findings:
        rid = f.resource_id
        if rid in contexts:
            continue
        exposure, tags = "unknown", {}
        if f.resource_type == "AWS_EC2_INSTANCE":
            exposure, tags = _ec2_exposure(_ec2_for(f), rid)
        elif f.resource_type in ("AWS_ECR_CONTAINER_IMAGE", "AWS_LAMBDA_FUNCTION"):
            exposure = "internal"  # refine via API Gateway / ALB mapping later
        contexts[rid] = AssetContext(
            resource_id=rid,
            exposure=exposure,
            criticality=_criticality_from_tags(tags),
            compensating_controls=_controls_from_tags(tags),
            tags=tags,
        )
    return contexts
