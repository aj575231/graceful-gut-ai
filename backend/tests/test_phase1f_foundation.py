"""Static guards for the Phase 1F infrastructure foundation.

`infrastructure/phase1f/template.yaml` cannot be exercised: it has not been
applied, there is no API Gateway to call, and this task creates none. What can
be checked is everything the template *says* -- and for an infrastructure stack
that is most of what matters, because the failures worth preventing here are
configuration failures, not runtime ones. A Web ACL associated with nothing, a
managed rule group promoted to Block before it was reviewed, a log format that
quietly carries a client IP, a Lambda permission scoped to the function instead
of the API, or a template that replaces the running function rather than
referencing it all look completely healthy right up to the moment they matter.

Two of these guards would otherwise pass vacuously and are therefore tested
against synthetic inputs first: the credential-header tripwire has nothing to
fire on until a public origin exists, and the redaction scans have nothing to
find while the values they forbid are absent. A scanner that silently matches
nothing protects nothing.

PyYAML arrives with `uvicorn[standard]`, so it is available in CI without
adding a dependency. It cannot parse CloudFormation short-form intrinsics on
its own -- `!Ref`, `!Sub`, `!GetAtt` -- so `CloudFormationLoader` below turns
them into their long-form mappings, which is also what makes them assertable.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.main import ALLOWED_ORIGINS

REPO_ROOT = Path(__file__).resolve().parents[2]
PHASE1F = REPO_ROOT / "infrastructure" / "phase1f"
TEMPLATE_PATH = PHASE1F / "template.yaml"
PARAMETERS_EXAMPLE = PHASE1F / "parameters.example.json"
RUNBOOK = PHASE1F / "administrator-runbook.md"
PHASE1F_README = PHASE1F / "README.md"
APP_MAIN = REPO_ROOT / "backend" / "app" / "main.py"


# ---------------------------------------------------------------------------
# Loading the template.
# ---------------------------------------------------------------------------


class CloudFormationLoader(yaml.SafeLoader):
    """A SafeLoader that understands CloudFormation's short-form tags."""


def _intrinsic(loader: yaml.Loader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    """Turn ``!Sub x`` into ``{"Fn::Sub": "x"}`` and ``!Ref x`` into ``{"Ref": x}``."""
    key = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
    value: Any
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
        if key == "Fn::GetAtt":
            value = value.split(".", 1)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {key: value}


CloudFormationLoader.add_multi_constructor("!", _intrinsic)

TEMPLATE: dict[str, Any] = yaml.load(
    TEMPLATE_PATH.read_text(encoding="utf-8"), Loader=CloudFormationLoader
)
TEMPLATE_TEXT = TEMPLATE_PATH.read_text(encoding="utf-8")

#: The parsed template, re-serialised. Absence checks run against this rather
#: than the raw file so that a comment *explaining* why something is absent --
#: "there is deliberately no {proxy+} path" -- does not read as the thing
#: itself. Redaction scans stay on the raw text, because a leaked account ID in
#: a comment is still a leaked account ID.
TEMPLATE_JSON = json.dumps(TEMPLATE)

RESOURCES: dict[str, Any] = TEMPLATE["Resources"]
PARAMETERS: dict[str, Any] = TEMPLATE["Parameters"]
CORS_CONTRACT: dict[str, Any] = TEMPLATE["Metadata"]["GracefulGutCorsContract"]

#: Every tracked file in this directory, for the redaction scans.
PHASE1F_FILES = sorted(path for path in PHASE1F.rglob("*") if path.is_file())


def of_type(type_name: str) -> dict[str, Any]:
    """Every resource of ``type_name``, keyed by logical ID."""
    return {
        logical_id: body
        for logical_id, body in RESOURCES.items()
        if body.get("Type") == type_name
    }


def walk(node: Any) -> Iterator[Any]:
    """Every dict, list, and scalar in ``node``, itself included."""
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def concrete(node: Any) -> Iterator[dict[str, Any]]:
    """Yield the real mappings in ``node``, unwrapping any ``Fn::If``.

    A conditional entry in a list arrives as ``{"Fn::If": [cond, value,
    {"Ref": "AWS::NoValue"}]}``. Both branches are worth asserting against: a
    setting that is safe only when a condition is false is not safe.
    """
    if not isinstance(node, dict) or node == {"Ref": "AWS::NoValue"}:
        return
    if "Fn::If" in node:
        for branch in node["Fn::If"][1:]:
            yield from concrete(branch)
    else:
        yield node


def waf_rules() -> list[dict[str, Any]]:
    return of_type("AWS::WAFv2::WebACL")["WebAcl"]["Properties"]["Rules"]


def managed_rule_groups() -> list[dict[str, Any]]:
    return [
        rule
        for rule in waf_rules()
        if "ManagedRuleGroupStatement" in rule.get("Statement", {})
    ]


# ---------------------------------------------------------------------------
# Template validity.
# ---------------------------------------------------------------------------

#: Every section CloudFormation recognises at the top level. Anything else is
#: rejected at apply time, which is the same failure mode the `_comment` block
#: in an IAM policy caused this repository once already.
CLOUDFORMATION_SECTIONS = {
    "AWSTemplateFormatVersion",
    "Description",
    "Metadata",
    "Transform",
    "Parameters",
    "Mappings",
    "Conditions",
    "Rules",
    "Resources",
    "Outputs",
}

PSEUDO_PARAMETERS = {
    "AWS::AccountId",
    "AWS::NoValue",
    "AWS::NotificationARNs",
    "AWS::Partition",
    "AWS::Region",
    "AWS::StackId",
    "AWS::StackName",
    "AWS::URLSuffix",
}

RESOURCE_TYPE = re.compile(r"^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$")


def test_template_has_the_required_top_level_sections() -> None:
    for section in ("AWSTemplateFormatVersion", "Resources", "Parameters"):
        assert section in TEMPLATE, f"{section} missing from the template"


def test_every_top_level_section_is_one_cloudformation_recognises() -> None:
    unknown = set(TEMPLATE) - CLOUDFORMATION_SECTIONS

    assert unknown == set(), f"CloudFormation would reject {sorted(unknown)}"


def test_the_sam_transform_is_declared() -> None:
    assert TEMPLATE["Transform"] == "AWS::Serverless-2016-10-31"


def test_the_transform_generates_nothing() -> None:
    """No AWS::Serverless resource, so the applied template equals this file.

    That equality is what makes an administrator-reviewed change set worth
    reviewing. A serverless resource would start generating resources that
    appear in the change set and nowhere in Git.
    """
    generated = [
        logical_id
        for logical_id, body in RESOURCES.items()
        if str(body.get("Type", "")).startswith("AWS::Serverless::")
    ]

    assert generated == []


def test_every_resource_declares_a_well_formed_type() -> None:
    malformed = [
        logical_id
        for logical_id, body in RESOURCES.items()
        if not RESOURCE_TYPE.match(str(body.get("Type", "")))
    ]

    assert malformed == []


def test_every_reference_names_something_that_exists() -> None:
    """A `Ref` to a typo is a stack that fails at create time, not at review."""
    known = set(RESOURCES) | set(PARAMETERS) | PSEUDO_PARAMETERS
    dangling = sorted(
        {
            node["Ref"]
            for node in walk(TEMPLATE)
            if isinstance(node, dict)
            and set(node) == {"Ref"}
            and isinstance(node["Ref"], str)
            and node["Ref"] not in known
        }
    )

    assert dangling == []


def test_every_resource_condition_is_defined() -> None:
    defined = set(TEMPLATE.get("Conditions", {}))
    used = {body["Condition"] for body in RESOURCES.values() if "Condition" in body}

    assert used <= defined, f"undefined condition(s): {sorted(used - defined)}"


def test_every_declared_condition_is_used() -> None:
    defined = set(TEMPLATE.get("Conditions", {}))
    used = {body["Condition"] for body in RESOURCES.values() if "Condition" in body}
    used |= {
        node["Fn::If"][0]
        for node in walk(TEMPLATE)
        if isinstance(node, dict) and "Fn::If" in node
    }

    assert defined - used == set(), f"dead condition(s): {sorted(defined - used)}"


def test_every_parameter_is_used() -> None:
    """An unused parameter is either a missing control or a stale one."""
    referenced = set()
    for node in walk(TEMPLATE):
        if isinstance(node, dict) and isinstance(node.get("Ref"), str):
            referenced.add(node["Ref"])
        if isinstance(node, dict) and isinstance(node.get("Fn::Sub"), str):
            referenced |= set(re.findall(r"\$\{([A-Za-z0-9:]+)\}", node["Fn::Sub"]))
    for condition in TEMPLATE.get("Conditions", {}).values():
        for node in walk(condition):
            if isinstance(node, dict) and isinstance(node.get("Ref"), str):
                referenced.add(node["Ref"])

    unused = sorted(set(PARAMETERS) - referenced)

    assert unused == []


def test_the_parameter_example_parses_and_covers_every_parameter() -> None:
    supplied = {
        entry["ParameterKey"]: entry["ParameterValue"]
        for entry in json.loads(PARAMETERS_EXAMPLE.read_text(encoding="utf-8"))
    }

    assert set(supplied) == set(PARAMETERS)
    assert supplied["EnableEducationRoute"] == "false"
    assert supplied["WafRateRuleAction"] == "Count"


# ---------------------------------------------------------------------------
# Redaction: no real account ID, API ID, domain, ARN, or URL.
# ---------------------------------------------------------------------------

ACCOUNT_ID = re.compile(r"\b\d{12}\b")
URL_LIKE = re.compile(r"https?://[^\s\"'`)\]}>,]*")

#: A URL is acceptable only when it is plainly not a real address: a
#: CloudFormation substitution, a placeholder, or part of a regular expression.
SUBSTITUTION_MARKERS = ("${", "<", "[", "(")

#: JSON Schema's draft identifier is a version string, not an address that is
#: ever fetched.
URL_ALLOWLIST = {"http://json-schema.org/draft-04/schema#"}


def literal_urls(text: str) -> list[str]:
    return [
        url
        for url in URL_LIKE.findall(text)
        if url not in URL_ALLOWLIST
        and not any(marker in url for marker in SUBSTITUTION_MARKERS)
    ]


def test_the_url_detector_catches_a_planted_address() -> None:
    """Without this the scan below could pass by matching nothing at all."""
    assert literal_urls("origin: https://a-real-site.example") != []
    assert literal_urls("origin: https://${RestApi}.execute-api.local") == []


def test_no_twelve_digit_account_id_appears() -> None:
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in PHASE1F_FILES
        if ACCOUNT_ID.search(path.read_text(encoding="utf-8", errors="replace"))
    ]

    assert offenders == [], "use the <AWS_ACCOUNT_ID> placeholder"


def test_no_literal_url_domain_or_api_id_appears() -> None:
    offenders = [
        f"{path.relative_to(REPO_ROOT)}: {found}"
        for path in PHASE1F_FILES
        if (found := literal_urls(path.read_text(encoding="utf-8", errors="replace")))
    ]

    assert offenders == [], (
        "a literal address reached a tracked file; the production origin is a "
        "deployment-time parameter and the API ID is a stack output"
    )


def test_the_example_parameter_file_carries_placeholders_only() -> None:
    raw = PARAMETERS_EXAMPLE.read_text(encoding="utf-8")

    assert "<AWS_ACCOUNT_ID>" in raw
    assert "<SQUARESPACE_PRODUCTION_ORIGIN>" in raw


# ---------------------------------------------------------------------------
# No browser-visible secret, and no wildcard CORS.
# ---------------------------------------------------------------------------

CREDENTIAL_NAMES = ("X-GG-Key", "GG_API_KEY")
LOOPBACK_PREFIXES = ("http://localhost", "http://127.0.0.1")
ALLOW_HEADERS = re.compile(r"allow_headers=\[(?P<items>[^\]]*)\]")


def key_header_offered_to_browsers(origins: list[str], main_source: str) -> bool:
    """Does the application invite a public browser to send the shared key?

    Only meaningful once a non-loopback origin exists. A loopback origin never
    leaves the machine, so a key header allowed there reaches no one.
    """
    if not [o for o in origins if not o.startswith(LOOPBACK_PREFIXES)]:
        return False
    match = ALLOW_HEADERS.search(main_source)
    items = match.group("items") if match else ""
    return "API_KEY_HEADER" in items or any(n in items for n in CREDENTIAL_NAMES)


def test_the_credential_header_tripwire_fires_on_a_public_origin() -> None:
    """The guard below is vacuous today; this proves it would not stay so."""
    source = 'allow_headers=["Content-Type", API_KEY_HEADER],'

    assert key_header_offered_to_browsers(["https://example.invalid"], source)
    assert not key_header_offered_to_browsers(["http://localhost:3000"], source)
    assert not key_header_offered_to_browsers(
        ["https://example.invalid"], 'allow_headers=["Content-Type"],'
    )


def test_the_shared_key_is_never_offered_to_a_public_browser_origin() -> None:
    """`X-GG-Key` is one static secret with no identity and no revocation.

    A browser told it may send that header is a browser that has been given
    it. This fails the moment a production origin is added to the application
    while the key header is still in the allowed list -- which is exactly when
    the mistake would otherwise ship.
    """
    assert not key_header_offered_to_browsers(
        ALLOWED_ORIGINS, APP_MAIN.read_text(encoding="utf-8")
    )


def test_the_cors_contract_offers_no_credential_header() -> None:
    assert CORS_CONTRACT["AllowedRequestHeaders"] == ["Content-Type"]
    assert CORS_CONTRACT["BrowserVisibleCredentialHeaders"] == []


def test_no_credential_name_appears_in_the_template() -> None:
    offenders = [name for name in CREDENTIAL_NAMES if name in TEMPLATE_JSON]

    assert offenders == []


def test_the_cors_contract_forbids_wildcards_and_credentials() -> None:
    assert CORS_CONTRACT["AllowCredentials"] is False
    assert CORS_CONTRACT["WildcardOriginPermitted"] is False
    assert CORS_CONTRACT["AllowedMethods"] == ["GET", "POST", "OPTIONS"]
    assert CORS_CONTRACT["ExposedResponseHeaders"] == []


@pytest.mark.parametrize("candidate", ["*", "https://*.example", "*.example", ""])
def test_the_production_origin_parameter_rejects_wildcards(candidate: str) -> None:
    pattern = re.compile(PARAMETERS["ProductionOrigin"]["AllowedPattern"])

    assert not pattern.match(candidate)


@pytest.mark.parametrize(
    "candidate", ["http://insecure.example", "https://a.example/x"]
)
def test_the_production_origin_parameter_requires_a_bare_https_origin(
    candidate: str,
) -> None:
    pattern = re.compile(PARAMETERS["ProductionOrigin"]["AllowedPattern"])

    assert not pattern.match(candidate)


def test_the_production_origin_parameter_accepts_an_exact_https_origin() -> None:
    pattern = re.compile(PARAMETERS["ProductionOrigin"]["AllowedPattern"])

    assert pattern.match("https://a-site.example")


def test_the_development_origin_is_separately_parameterized_and_optional() -> None:
    development = PARAMETERS["DevelopmentOrigin"]
    pattern = re.compile(development["AllowedPattern"])

    assert development["Default"] == ""
    assert pattern.match("")
    assert pattern.match("http://localhost:5173")
    assert not pattern.match("*")


def test_the_allowed_origins_output_flows_infrastructure_to_application() -> None:
    """Exported by the stack that protects the application, never the reverse."""
    output = TEMPLATE["Outputs"]["AllowedOrigins"]

    assert "Export" in output


# ---------------------------------------------------------------------------
# The public education route is disabled by default.
# ---------------------------------------------------------------------------

EDUCATION_LOGICAL_IDS = (
    "V1Resource",
    "EducationResource",
    "EducationAskResource",
    "EducationRequestValidator",
    "EducationAskModel",
    "EducationAskPostMethod",
    "EducationAskOptionsMethod",
    "EducationAskPostInvokePermission",
    "EducationAskOptionsInvokePermission",
)


def test_the_education_route_is_disabled_by_default() -> None:
    parameter = PARAMETERS["EnableEducationRoute"]

    assert parameter["Default"] == "false"
    assert parameter["AllowedValues"] == ["false", "true"]


def test_every_education_resource_is_conditional() -> None:
    unguarded = [
        logical_id
        for logical_id in EDUCATION_LOGICAL_IDS
        if RESOURCES[logical_id].get("Condition") != "EducationRouteEnabled"
    ]

    assert unguarded == [], "an education resource would be created by default"


def test_the_education_condition_is_true_only_for_the_explicit_string() -> None:
    condition = TEMPLATE["Conditions"]["EducationRouteEnabled"]

    assert condition == {"Fn::Equals": [{"Ref": "EnableEducationRoute"}, "true"]}


# ---------------------------------------------------------------------------
# Request validation on the education route.
# ---------------------------------------------------------------------------


def test_request_validation_validates_the_body_and_the_parameters() -> None:
    """Validation is off by default; a model attached without it does nothing."""
    validator = RESOURCES["EducationRequestValidator"]["Properties"]

    assert validator["ValidateRequestBody"] is True
    assert validator["ValidateRequestParameters"] is True


def test_the_request_model_caps_length_and_forbids_unexpected_fields() -> None:
    schema = RESOURCES["EducationAskModel"]["Properties"]["Schema"]

    assert schema["type"] == "object"
    assert schema["required"] == ["message"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["message"]["maxLength"] == 2000
    assert schema["properties"]["message"]["type"] == "string"


def test_the_model_is_registered_for_json_and_for_the_default_content_type() -> None:
    """API Gateway skips body validation when no model matches the content type.

    Without the `$default` key a body sent as `text/plain` reaches the function
    unvalidated, and `PassthroughBehavior` does not close that on an AWS_PROXY
    integration.
    """
    models = RESOURCES["EducationAskPostMethod"]["Properties"]["RequestModels"]

    assert set(models) == {"application/json", "$default"}
    assert models["application/json"] == {"Ref": "EducationAskModel"}
    assert models["$default"] == {"Ref": "EducationAskModel"}


def test_the_education_method_requires_a_content_type_header() -> None:
    parameters = RESOURCES["EducationAskPostMethod"]["Properties"]["RequestParameters"]

    assert parameters["method.request.header.Content-Type"] is True


def test_the_education_integration_never_passes_an_unmapped_body_through() -> None:
    integration = RESOURCES["EducationAskPostMethod"]["Properties"]["Integration"]

    assert integration["PassthroughBehavior"] == "NEVER"


def test_the_education_method_is_wired_to_the_request_validator() -> None:
    method = RESOURCES["EducationAskPostMethod"]["Properties"]

    assert method["RequestValidatorId"] == {"Ref": "EducationRequestValidator"}


# ---------------------------------------------------------------------------
# WAF.
# ---------------------------------------------------------------------------


def test_the_web_acl_is_regional_and_defaults_to_allow() -> None:
    acl = of_type("AWS::WAFv2::WebACL")["WebAcl"]["Properties"]

    assert acl["Scope"] == "REGIONAL"
    assert acl["DefaultAction"] == {"Allow": {}}


def test_the_size_rule_blocks_bodies_over_4096_bytes() -> None:
    rule = next(r for r in waf_rules() if r["Name"] == "BlockOversizedBodies")
    statement = rule["Statement"]["SizeConstraintStatement"]

    assert rule["Action"] == {"Block": {}}
    assert statement["Size"] == 4096
    assert statement["ComparisonOperator"] == "GT"
    assert "Body" in statement["FieldToMatch"]


def test_the_size_rule_treats_an_unmeasurable_body_as_a_match() -> None:
    """A body past the inspection limit cannot be measured.

    `CONTINUE` would let the very largest bodies -- the ones the rule exists
    for -- through unblocked.
    """
    rule = next(r for r in waf_rules() if r["Name"] == "BlockOversizedBodies")
    body = rule["Statement"]["SizeConstraintStatement"]["FieldToMatch"]["Body"]

    assert body["OversizeHandling"] == "MATCH"


def test_the_body_inspection_limit_is_configured_for_api_gateway() -> None:
    """16 KB is the API Gateway default. 8 KB is ALB and AppSync, not this."""
    acl = of_type("AWS::WAFv2::WebACL")["WebAcl"]["Properties"]
    association = acl["AssociationConfig"]["RequestBody"]

    assert set(association) == {"API_GATEWAY"}
    assert association["API_GATEWAY"]["DefaultSizeInspectionLimit"] == "KB_16"


def test_the_method_rule_allows_only_get_post_and_options() -> None:
    rule = next(r for r in waf_rules() if r["Name"] == "BlockUnsupportedMethods")
    inner = rule["Statement"]["NotStatement"]["Statement"]["OrStatement"]["Statements"]
    allowed = {branch["ByteMatchStatement"]["SearchString"] for branch in inner}

    assert rule["Action"] == {"Block": {}}
    assert allowed == {"GET", "POST", "OPTIONS"}
    for branch in inner:
        assert branch["ByteMatchStatement"]["PositionalConstraint"] == "EXACTLY"
        assert "Method" in branch["ByteMatchStatement"]["FieldToMatch"]


def test_every_managed_rule_group_begins_in_count() -> None:
    """Ordinary descriptions of gut symptoms trip SQLi and XSS heuristics.

    Blocking a user describing their symptoms is a product failure, not a
    security win, so every group is observed before it is allowed to reject.
    """
    groups = managed_rule_groups()

    assert len(groups) == 5, "expected five managed rule groups"
    for rule in groups:
        assert rule.get("OverrideAction") == {"Count": {}}, (
            f"{rule['Name']} does not begin in Count"
        )
        assert "Action" not in rule


def test_the_expected_managed_rule_groups_are_present() -> None:
    names = {
        rule["Statement"]["ManagedRuleGroupStatement"]["Name"]
        for rule in managed_rule_groups()
    }

    assert names == {
        "AWSManagedRulesAmazonIpReputationList",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesSQLiRuleSet",
        "AWSManagedRulesAnonymousIpList",
    }


def test_the_anonymous_ip_rule_is_not_block() -> None:
    """Blocking VPN and Tor traffic on a gut-health service harms exactly the
    users most likely to want privacy while researching a sensitive symptom."""
    rule = next(
        r
        for r in managed_rule_groups()
        if r["Statement"]["ManagedRuleGroupStatement"]["Name"]
        == "AWSManagedRulesAnonymousIpList"
    )

    assert rule["OverrideAction"] == {"Count": {}}
    assert "Block" not in json.dumps(rule)


def test_no_waf_logging_configuration_exists() -> None:
    """WAF logs always carry the client IP and cannot be configured to drop it."""
    assert of_type("AWS::WAFv2::LoggingConfiguration") == {}
    assert "LoggingConfiguration" not in TEMPLATE_JSON


def test_the_rate_rules_are_parameterized_and_respect_the_aws_floor() -> None:
    """AWS rejects a rate-based limit below 100 per window.

    The ADR proposes 40 and 60 per five minutes for the chat route; neither is
    expressible as a WAF rule, and MinValue makes that fail at validation
    rather than at apply time.
    """
    for name in ("WafOverallRateLimit", "WafEducationRouteRateLimit"):
        assert PARAMETERS[name]["MinValue"] == 100

    rate_rules = [
        rule
        for rule in waf_rules()
        if "RateBasedStatement" in rule.get("Statement", {})
    ]

    assert len(rate_rules) == 2
    for rule in rate_rules:
        statement = rule["Statement"]["RateBasedStatement"]
        assert statement["AggregateKeyType"] == "IP"
        assert isinstance(statement["Limit"], dict) and "Ref" in statement["Limit"]


def test_the_rate_rules_ship_in_count() -> None:
    """A rate rule in Count protects nothing, which is why the action is a
    parameter and why the runbook makes Block a precondition of launch."""
    assert PARAMETERS["WafRateRuleAction"]["Default"] == "Count"
    assert set(PARAMETERS["WafRateRuleAction"]["AllowedValues"]) == {"Count", "Block"}


def test_no_geographic_restriction_is_configured() -> None:
    """Educational content is not geographically limited; clinical services are."""
    assert "GeoMatchStatement" not in TEMPLATE_JSON


def test_no_captcha_or_challenge_action_is_configured() -> None:
    """An interactive puzzle in front of someone seeking urgent guidance is a
    harm, and neither is needed before abuse is actually observed."""
    for token in ("Captcha", "CAPTCHA", "Challenge"):
        assert token not in TEMPLATE_JSON


def test_the_web_acl_is_associated_with_the_stage() -> None:
    """A Web ACL associated with nothing inspects nothing while looking healthy."""
    association = of_type("AWS::WAFv2::WebACLAssociation")

    assert len(association) == 1
    properties = next(iter(association.values()))["Properties"]
    resource_arn = properties["ResourceArn"]["Fn::Sub"]

    assert "/restapis/${RestApi}/stages/${StageName}" in resource_arn
    assert properties["WebACLArn"] == {"Fn::GetAtt": ["WebAcl", "Arn"]}


# ---------------------------------------------------------------------------
# Access logging.
# ---------------------------------------------------------------------------

#: The only context variables the log format may carry. Every one is either
#: server-generated or an enumerated protocol value.
PERMITTED_LOG_FIELDS = {
    "$context.requestId",
    "$context.requestTime",
    "$context.resourcePath",
    "$context.status",
    "$context.integration.status",
    "$context.responseLatency",
    "$context.responseLength",
}

FORBIDDEN_LOG_TOKENS = (
    "identity",
    "sourceIp",
    "userAgent",
    "$input",
    ".header.",
    "querystring",
    "authorizer",
    "body",
    "Authorization",
)


def access_log_format() -> str:
    stage = RESOURCES["Stage"]["Properties"]
    return stage["AccessLogSetting"]["Format"]


def test_the_access_log_format_carries_only_permitted_fields() -> None:
    fields = set(json.loads(access_log_format()).values())

    assert fields == PERMITTED_LOG_FIELDS


def test_the_access_log_format_excludes_ip_headers_queries_and_bodies() -> None:
    lowered = access_log_format().lower()
    offenders = [token for token in FORBIDDEN_LOG_TOKENS if token.lower() in lowered]

    assert offenders == []


def test_the_access_log_destination_is_the_stack_owned_group() -> None:
    setting = RESOURCES["Stage"]["Properties"]["AccessLogSetting"]

    assert setting["DestinationArn"] == {"Fn::GetAtt": ["AccessLogGroup", "Arn"]}


def test_access_log_retention_is_bounded() -> None:
    """14 days for application logs, 30 the maximum for anything security-relevant."""
    retention = PARAMETERS["AccessLogRetentionDays"]

    assert retention["Default"] == 14
    assert max(retention["AllowedValues"]) == 30


def test_data_trace_logging_is_disabled_on_every_method_setting() -> None:
    """DataTrace writes full request and response bodies to CloudWatch.

    Turned on, it would put user health text in a log the moment the education
    route is enabled -- so it is asserted off on every setting, including the
    ones that only exist when a condition is true.
    """
    settings = [
        entry
        for raw in RESOURCES["Stage"]["Properties"]["MethodSettings"]
        for entry in concrete(raw)
    ]

    assert len(settings) == 3
    for entry in settings:
        assert entry["DataTraceEnabled"] is False
        assert entry["LoggingLevel"] != "INFO"


def test_throttles_are_parameterized_on_every_method_setting() -> None:
    settings = [
        entry
        for raw in RESOURCES["Stage"]["Properties"]["MethodSettings"]
        for entry in concrete(raw)
    ]

    for entry in settings:
        for key in ("ThrottlingRateLimit", "ThrottlingBurstLimit"):
            assert "Ref" in entry[key], f"{key} is hard-coded"


# ---------------------------------------------------------------------------
# The function is referenced, never replaced. Nothing reopens the Function URL.
# ---------------------------------------------------------------------------


def test_the_template_references_rather_than_replaces_the_function() -> None:
    forbidden = (
        "AWS::Lambda::Function",
        "AWS::Serverless::Function",
        "AWS::Lambda::Alias",
        "AWS::Lambda::Version",
        "AWS::Lambda::EventInvokeConfig",
    )
    declared = [name for name in forbidden if of_type(name)]

    assert declared == []
    assert PARAMETERS["ApplicationFunctionArn"]["Type"] == "String"


def test_the_function_arn_parameter_is_constrained_to_a_function_arn() -> None:
    pattern = re.compile(PARAMETERS["ApplicationFunctionArn"]["AllowedPattern"])

    assert not pattern.match("not-an-arn")
    assert not pattern.match("arn:aws:lambda:us-east-2:123456789012:function:a/b")


def test_no_function_url_resource_or_permission_appears() -> None:
    """Function URL administration is administrator-only and stays outside IaC."""
    assert of_type("AWS::Lambda::Url") == {}
    for token in ("FunctionUrl", "InvokeFunctionUrl", "FunctionUrlAuthType"):
        assert token not in TEMPLATE_JSON


def test_every_lambda_permission_is_source_arn_scoped_to_this_api() -> None:
    """A permission scoped to the function alone lets any API in the account
    invoke it; one scoped to the API but not the method survives a new route."""
    permissions = of_type("AWS::Lambda::Permission")

    assert permissions, "expected at least one invoke permission"
    for logical_id, body in permissions.items():
        properties = body["Properties"]
        assert properties["Principal"] == "apigateway.amazonaws.com"
        assert properties["Action"] == "lambda:InvokeFunction"
        assert properties["FunctionName"] == {"Ref": "ApplicationFunctionArn"}

        source_arn = properties["SourceArn"]["Fn::Sub"]
        assert "${RestApi}/${StageName}/" in source_arn, logical_id
        assert "*" not in source_arn, f"{logical_id} is wildcard-scoped"


def test_the_template_does_not_manage_reserved_concurrency() -> None:
    """Reserved concurrency stays with the application path: setting it to 0 is
    the emergency kill switch and must not wait for an administrator."""
    assert "ReservedConcurrentExecutions" not in TEMPLATE_JSON
    assert "ProvisionedConcurrency" not in TEMPLATE_JSON


def test_no_budget_resource_is_created() -> None:
    assert of_type("AWS::Budgets::Budget") == {}


def test_no_iam_role_or_policy_is_created() -> None:
    """IAM belongs to the administrator, applied from the reference documents in
    infrastructure/phase1e/, not generated as a side effect of this stack."""
    for name in ("AWS::IAM::Role", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
        assert of_type(name) == {}


# ---------------------------------------------------------------------------
# The public surface is the minimum one.
# ---------------------------------------------------------------------------

PROHIBITED_PATH_PARTS = (
    "docs",
    "redoc",
    "openapi",
    "swagger",
    "admin",
    "debug",
    "internal",
    "schedul",
)


def path_parts() -> list[str]:
    return [
        body["Properties"]["PathPart"]
        for body in of_type("AWS::ApiGateway::Resource").values()
    ]


def route_surface() -> list[str]:
    """Every string in the template that decides what path is reachable.

    Prose is deliberately excluded: this stack's description calls it
    "administrator-controlled", and a scan of the whole document would read
    that as an `/admin` route.
    """
    return path_parts() + [
        body["Properties"]["SourceArn"]["Fn::Sub"]
        for body in of_type("AWS::Lambda::Permission").values()
    ]


def test_no_prohibited_route_is_declared() -> None:
    """No docs, no schema, no administrative route, and -- per CLAUDE.md --
    nothing resembling clinical scheduling, which stays a separate system."""
    offenders = [
        f"{value}: {prohibited}"
        for value in route_surface()
        for prohibited in PROHIBITED_PATH_PARTS
        if prohibited in value.lower()
    ]

    assert offenders == []


def test_nothing_is_served_at_the_api_root() -> None:
    """The application answers `/` with a service banner. It is not public."""
    served_at_root = [
        logical_id
        for logical_id, body in of_type("AWS::ApiGateway::Method").items()
        if body["Properties"]["ResourceId"]
        == {"Fn::GetAtt": ["RestApi", "RootResourceId"]}
    ]

    assert served_at_root == []


def test_the_declared_paths_are_exactly_health_and_the_education_route() -> None:
    assert set(path_parts()) == {"health", "v1", "education", "ask"}


def test_no_greedy_proxy_resource_exists() -> None:
    """A {proxy+} path would expose the application's whole route table -- `/`,
    `/version`, and anything added later -- through one line of template."""
    assert not any("{" in part for part in path_parts())
    assert "proxy+" not in TEMPLATE_JSON


def test_only_get_post_and_options_methods_are_declared() -> None:
    methods = {
        body["Properties"]["HttpMethod"]
        for body in of_type("AWS::ApiGateway::Method").values()
    }

    assert methods <= {"GET", "POST", "OPTIONS"}
    assert "ANY" not in methods


def test_every_method_is_anonymous_and_takes_no_api_key() -> None:
    """There are no accounts, so there is no user to authenticate. Abuse control
    is the whole of the defence, and the design says so rather than shipping a
    client-visible token and calling it security."""
    for logical_id, body in of_type("AWS::ApiGateway::Method").items():
        properties = body["Properties"]
        assert properties["AuthorizationType"] == "NONE", logical_id
        assert properties["ApiKeyRequired"] is False, logical_id


def test_every_method_proxies_to_the_referenced_function() -> None:
    for logical_id, body in of_type("AWS::ApiGateway::Method").items():
        integration = body["Properties"]["Integration"]
        assert integration["Type"] == "AWS_PROXY", logical_id
        assert "${ApplicationFunctionArn}" in integration["Uri"]["Fn::Sub"]


def test_preflight_reaches_the_application_on_every_public_resource() -> None:
    """On a REST API, OPTIONS is not automatic: unless it is wired to the same
    integration, API Gateway answers it itself -- typically 403 -- and the
    preflight fails before the application's CORS middleware is consulted."""
    options = {
        body["Properties"]["ResourceId"]["Ref"]
        for body in of_type("AWS::ApiGateway::Method").values()
        if body["Properties"]["HttpMethod"] == "OPTIONS"
    }

    assert options == {"HealthResource", "EducationAskResource"}


def test_the_stage_and_the_deployment_are_both_explicit() -> None:
    stage = of_type("AWS::ApiGateway::Stage")
    deployment = of_type("AWS::ApiGateway::Deployment")

    assert len(stage) == 1 and len(deployment) == 1
    assert "StageName" not in deployment["Deployment"]["Properties"], (
        "a StageName on the Deployment would create a second, implicit stage"
    )
    assert stage["Stage"]["Properties"]["DeploymentId"] == {"Ref": "Deployment"}


def test_the_api_is_regional() -> None:
    api = of_type("AWS::ApiGateway::RestApi")["RestApi"]["Properties"]

    assert api["EndpointConfiguration"]["Types"] == ["REGIONAL"]


# ---------------------------------------------------------------------------
# The documentation carries the procedures, and records that none was run.
# ---------------------------------------------------------------------------


def test_the_runbook_documents_administrator_reviewed_change_sets() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    for token in ("create-change-set", "describe-change-set", "execute-change-set"):
        assert token in runbook, f"{token} missing from the runbook"


@pytest.mark.parametrize(
    "heading",
    ["## 1. Create", "## 2. Update", "## 3. Verification", "## 4. Rollback"],
)
def test_the_runbook_covers_every_required_procedure(heading: str) -> None:
    assert heading in RUNBOOK.read_text(encoding="utf-8")


def test_the_runbook_documents_the_reserved_concurrency_kill_switch() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert "put-function-concurrency" in runbook
    assert "--reserved-concurrent-executions 0" in runbook


def test_the_runbook_records_that_no_procedure_was_executed() -> None:
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert "None of them was executed" in runbook


def test_the_readme_separates_infrastructure_from_application_ownership() -> None:
    readme = PHASE1F_README.read_text(encoding="utf-8")

    assert "Owned by the application path" in readme
    assert "Reserved concurrency" in readme
    assert "referenced, never managed" in readme.lower()
