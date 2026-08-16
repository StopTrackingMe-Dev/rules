#!/usr/bin/env python3
"""Validate the rule sources and build the single subscription bundle.

The Android RuleParser remains the final authority. This dependency-free
validator mirrors its structural limits so malformed or dangerous rule data
fails in CI before a release is published.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_BUNDLE_BYTES = 512 * 1024
MAX_RULES_PER_BUNDLE = 32
MAX_SELECTORS = 24
MAX_CLICKABLE_PARENT_DEPTH = 8
MAX_REDIRECTS = 5
MAX_HOSTS = 32
MAX_PARAMETERS = 128
MAX_PREVIEW_SELECTORS = 8
MAX_PREVIEW_FALLBACK_REQUESTS = 3
MAX_ACCESS_FAILURE_RULES = 8
MAX_PREVIEW_KEY_LENGTH = 80
MAX_HEADERS = 16
MAX_FORM_PARAMETERS = 24
MAX_HEADER_NAME_LENGTH = 64
MAX_HEADER_VALUE_LENGTH = 512
MAX_TEMPLATE_LENGTH = 1_024
MAX_ID_LENGTH = 80
MAX_NAME_LENGTH = 80
MAX_SOURCE_LENGTH = 512
MAX_PACKAGE_LENGTH = 160
MAX_SELECTOR_TEXT = 256
MAX_REGEX_LENGTH = 256
MAX_HOST_LENGTH = 253
MAX_PARAMETER_LENGTH = 64
MAX_CLIPBOARD_INPUT_LENGTH = 32 * 1024
MIN_PANEL_TIMEOUT_MS = 1_000
MAX_PANEL_TIMEOUT_MS = 10_000
MIN_SETTLE_DELAY_MS = 100
MAX_SETTLE_DELAY_MS = 2_000
MIN_NETWORK_TIMEOUT_MS = 500
MAX_NETWORK_TIMEOUT_MS = 10_000

PACKAGE_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
HOST_PATTERN = re.compile(
    r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._-]+$")
PARAMETER_PATTERN = re.compile(r"[A-Za-z0-9._~-]+$")
PREVIEW_KEY_PATTERN = re.compile(r"[A-Za-z0-9._:-]+$")
PREVIEW_JSON_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z0-9_:-]+|\*)(?:\.(?:[A-Za-z0-9_:-]+|\*))*$"
)
HEADER_NAME_PATTERN = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
INTEGER_PATTERN = re.compile(r"-?(0|[1-9][0-9]*)$")


class ValidationError(ValueError):
    pass


def fail(path: str, message: str) -> None:
    raise ValidationError(f"{path}: {message}")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_BUNDLE_BYTES:
        fail(path.name, f"file is larger than {MAX_BUNDLE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValidationError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as error:
        fail(path.name, f"invalid UTF-8 or JSON: {error}")
    if not isinstance(value, dict):
        fail(path.name, "root must be an object")
    return value


def require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(path, "must be an object")
    return value


def require_array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        fail(path, "must be an array")
    return value


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        fail(path, "must be a string")
    return value


def require_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail(path, "must be an integer")
    if not INTEGER_PATTERN.fullmatch(str(value)):
        fail(path, "must be a decimal integer")
    return value


def require_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        fail(path, "must be a boolean")
    return value


def optional_string(obj: dict[str, Any], name: str, path: str) -> str | None:
    if name not in obj or obj[name] is None:
        return None
    return require_string(obj[name], f"{path}.{name}")


def optional_bool(obj: dict[str, Any], name: str, path: str) -> bool | None:
    if name not in obj or obj[name] is None:
        return None
    return require_bool(obj[name], f"{path}.{name}")


def require_keys(
    obj: dict[str, Any],
    required: set[str],
    optional: set[str],
    path: str,
) -> None:
    unknown = set(obj) - required - optional
    if unknown:
        fail(path, f"unknown field(s): {', '.join(sorted(unknown))}")
    missing = required - set(obj)
    if missing:
        fail(path, f"missing field(s): {', '.join(sorted(missing))}")


def validate_text(value: Any, path: str, maximum: int) -> str:
    text = require_string(value, path)
    if not text.strip() or len(text) > maximum or any(ord(char) < 32 for char in text):
        fail(path, "must be non-blank, bounded, and contain no control characters")
    return text


def validate_regex(value: Any, path: str) -> str:
    expression = require_string(value, path)
    if not expression or len(expression) > MAX_REGEX_LENGTH:
        fail(path, "has an invalid length")
    # RE2/J intentionally rejects look-around and backreferences.
    if re.search(r"\\[1-9]|\(\?[=!<]", expression):
        fail(path, "uses a construct unsupported by RE2/J")
    try:
        re.compile(expression)
    except re.error as error:
        fail(path, f"is not a valid regular expression: {error}")
    return expression


def validate_host(value: Any, path: str) -> str:
    host = require_string(value, path)
    if len(host) > MAX_HOST_LENGTH or any(char in host for char in "*/:"):
        fail(path, "has an invalid host format")
    try:
        normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        fail(path, f"has an invalid host format: {error}")
    if not HOST_PATTERN.fullmatch(normalized):
        fail(path, "has an invalid host format")
    return normalized


def validate_string_list(
    value: Any,
    path: str,
    maximum: int,
    item_validator=None,
) -> list[str]:
    values = require_array(value, path)
    if len(values) > maximum:
        fail(path, f"contains more than {maximum} items")
    result = []
    for index, item in enumerate(values):
        item_path = f"{path}[{index}]"
        result.append(item_validator(item, item_path) if item_validator else require_string(item, item_path))
    return result


def validate_hosts(value: Any, path: str) -> list[str]:
    return validate_string_list(value, path, MAX_HOSTS, validate_host)


def validate_parameters(value: Any, path: str) -> list[str]:
    def validate_parameter(item: Any, item_path: str) -> str:
        parameter = require_string(item, item_path)
        if not parameter or len(parameter) > MAX_PARAMETER_LENGTH or not PARAMETER_PATTERN.fullmatch(parameter):
            fail(item_path, "has an invalid parameter name")
        return parameter.lower()

    return validate_string_list(value, path, MAX_PARAMETERS, validate_parameter)


def validate_selector(value: Any, path: str) -> None:
    selector = require_object(value, path)
    require_keys(
        selector,
        required=set(),
        optional={"resourceId", "textRegex", "descriptionRegex", "className", "clickable"},
        path=path,
    )
    resource_id = optional_string(selector, "resourceId", path)
    text_regex = selector.get("textRegex")
    description_regex = selector.get("descriptionRegex")
    class_name = optional_string(selector, "className", path)
    optional_bool(selector, "clickable", path)
    if resource_id is not None:
        validate_text(resource_id, f"{path}.resourceId", MAX_SELECTOR_TEXT)
    if text_regex is not None:
        validate_regex(text_regex, f"{path}.textRegex")
    if description_regex is not None:
        validate_regex(description_regex, f"{path}.descriptionRegex")
    if class_name is not None:
        validate_text(class_name, f"{path}.className", MAX_SELECTOR_TEXT)
    if resource_id is None and text_regex is None and description_regex is None and class_name is None:
        fail(path, "must contain at least one matching field")


def validate_selectors(value: Any, path: str) -> None:
    selectors = require_array(value, path)
    if not 1 <= len(selectors) <= MAX_SELECTORS:
        fail(path, f"must contain 1..{MAX_SELECTORS} selectors")
    for index, selector in enumerate(selectors):
        validate_selector(selector, f"{path}[{index}]")


def validate_target(value: Any, path: str) -> None:
    target = require_object(value, path)
    require_keys(target, {"packageName", "minVersionCode", "maxVersionCode"}, set(), path)
    package_name = require_string(target["packageName"], f"{path}.packageName")
    if len(package_name) > MAX_PACKAGE_LENGTH or not PACKAGE_PATTERN.fullmatch(package_name):
        fail(f"{path}.packageName", "has an invalid package name")
    minimum = target["minVersionCode"]
    maximum = target["maxVersionCode"]
    if minimum is not None:
        minimum = require_int(minimum, f"{path}.minVersionCode")
        if minimum < 0:
            fail(f"{path}.minVersionCode", "must not be negative")
    if maximum is not None:
        maximum = require_int(maximum, f"{path}.maxVersionCode")
        if maximum < 0:
            fail(f"{path}.maxVersionCode", "must not be negative")
    if minimum is not None and maximum is not None and minimum > maximum:
        fail(path, "minVersionCode must not exceed maxVersionCode")


def validate_source(value: Any, path: str) -> None:
    source = require_object(value, path)
    require_keys(source, {"kind", "reference"}, set(), path)
    if require_string(source["kind"], f"{path}.kind").upper() != "REMOTE":
        fail(f"{path}.kind", "external rules must declare REMOTE")
    validate_text(source["reference"], f"{path}.reference", MAX_SOURCE_LENGTH)


def validate_clipboard(value: Any, path: str) -> None:
    clipboard = require_object(value, path)
    require_keys(clipboard, {"urlRegex", "maxInputLength"}, set(), path)
    validate_regex(clipboard["urlRegex"], f"{path}.urlRegex")
    maximum = require_int(clipboard["maxInputLength"], f"{path}.maxInputLength")
    if not 1 <= maximum <= MAX_CLIPBOARD_INPUT_LENGTH:
        fail(f"{path}.maxInputLength", "is outside the supported range")


def validate_access_failures(value: Any, path: str) -> None:
    failures = require_array(value, path)
    if not 1 <= len(failures) <= MAX_ACCESS_FAILURE_RULES:
        fail(path, f"must contain 1..{MAX_ACCESS_FAILURE_RULES} entries")
    for index, item in enumerate(failures):
        item_path = f"{path}[{index}]"
        failure = require_object(item, item_path)
        require_keys(failure, {"urlRegex"}, {"recoveryQueryParameter"}, item_path)
        validate_regex(failure["urlRegex"], f"{item_path}.urlRegex")
        recovery = optional_string(failure, "recoveryQueryParameter", item_path)
        if recovery is not None and (
            not recovery
            or len(recovery) > MAX_PARAMETER_LENGTH
            or not PARAMETER_PATTERN.fullmatch(recovery)
        ):
            fail(f"{item_path}.recoveryQueryParameter", "has an invalid parameter name")


def validate_redirect_policy(value: Any, path: str) -> None:
    policy = require_object(value, path)
    require_keys(
        policy,
        {"shortLinkHosts", "allowedFinalHosts", "maxRedirects", "requireHttps", "connectTimeoutMs", "readTimeoutMs"},
        {"stopAtAllowedFinalHost", "accessFailures"},
        path,
    )
    validate_hosts(policy["shortLinkHosts"], f"{path}.shortLinkHosts")
    final_hosts = validate_hosts(policy["allowedFinalHosts"], f"{path}.allowedFinalHosts")
    if not final_hosts:
        fail(f"{path}.allowedFinalHosts", "must not be empty")
    redirects = require_int(policy["maxRedirects"], f"{path}.maxRedirects")
    if not 0 <= redirects <= MAX_REDIRECTS:
        fail(f"{path}.maxRedirects", "is outside the supported range")
    require_bool(policy["requireHttps"], f"{path}.requireHttps")
    for name in ("connectTimeoutMs", "readTimeoutMs"):
        timeout = require_int(policy[name], f"{path}.{name}")
        if not MIN_NETWORK_TIMEOUT_MS <= timeout <= MAX_NETWORK_TIMEOUT_MS:
            fail(f"{path}.{name}", "is outside the supported range")
    optional_bool(policy, "stopAtAllowedFinalHost", path)
    if "accessFailures" in policy:
        validate_access_failures(policy["accessFailures"], f"{path}.accessFailures")


def validate_headers(value: Any, path: str) -> None:
    headers = require_object(value, path)
    if len(headers) > MAX_HEADERS:
        fail(path, f"contains more than {MAX_HEADERS} headers")
    for name, header_value in headers.items():
        if not isinstance(name, str) or not name or len(name) > MAX_HEADER_NAME_LENGTH or not HEADER_NAME_PATTERN.fullmatch(name):
            fail(path, "contains an invalid header name")
        validate_text(header_value, f"{path}.{name}", MAX_HEADER_VALUE_LENGTH)


def validate_string_map(value: Any, path: str, maximum: int, value_length: int) -> None:
    values = require_object(value, path)
    if len(values) > maximum:
        fail(path, f"contains more than {maximum} entries")
    for name, item in values.items():
        if not isinstance(name, str) or not name or len(name) > MAX_HEADER_NAME_LENGTH:
            fail(path, "contains an invalid key")
        validate_text(item, f"{path}.{name}", value_length)


def validate_preview_selector(value: Any, path: str, allow_html_title: bool) -> None:
    selector = require_object(value, path)
    require_keys(selector, {"type"}, {"key"}, path)
    selector_type = require_string(selector["type"], f"{path}.type").upper()
    key = optional_string(selector, "key", path)
    if selector_type == "HTML_TITLE":
        if not allow_html_title or key is not None:
            fail(path, "HTML_TITLE is not valid here")
    elif selector_type in {"META_PROPERTY", "META_NAME"}:
        if key is None or len(key) > MAX_PREVIEW_KEY_LENGTH or not PREVIEW_KEY_PATTERN.fullmatch(key):
            fail(f"{path}.key", "has an invalid metadata key")
    elif selector_type in {"JSON_PATH", "SCRIPT_JSON_PATH"}:
        if key is None or len(key) > MAX_PREVIEW_KEY_LENGTH or not PREVIEW_JSON_PATH_PATTERN.fullmatch(key):
            fail(f"{path}.key", "has an invalid JSON path")
    else:
        fail(f"{path}.type", "is not supported")


def validate_preview_selectors(value: Any, path: str, allow_html_title: bool) -> None:
    selectors = require_array(value, path)
    if not 1 <= len(selectors) <= MAX_PREVIEW_SELECTORS:
        fail(path, f"must contain 1..{MAX_PREVIEW_SELECTORS} selectors")
    for index, selector in enumerate(selectors):
        validate_preview_selector(selector, f"{path}[{index}]", allow_html_title)


def validate_signature(value: Any, path: str) -> None:
    signature = require_object(value, path)
    require_keys(signature, {"algorithm", "parameterName", "suffix"}, set(), path)
    if require_string(signature["algorithm"], f"{path}.algorithm").upper() != "MD5_CONCAT":
        fail(f"{path}.algorithm", "is not supported")
    parameter = require_string(signature["parameterName"], f"{path}.parameterName")
    if not 1 <= len(parameter) <= MAX_PARAMETER_LENGTH or not TOKEN_PATTERN.fullmatch(parameter):
        fail(f"{path}.parameterName", "has an invalid token")
    validate_text(signature["suffix"], f"{path}.suffix", MAX_HEADER_VALUE_LENGTH)


def validate_preview_request(value: Any, path: str) -> None:
    request = require_object(value, path)
    require_keys(
        request,
        {"urlRegex", "urlReplacement", "method", "headers", "responseType"},
        {"formParameters", "signature"},
        path,
    )
    validate_regex(request["urlRegex"], f"{path}.urlRegex")
    validate_text(request["urlReplacement"], f"{path}.urlReplacement", MAX_TEMPLATE_LENGTH)
    method = require_string(request["method"], f"{path}.method").upper()
    if method not in {"GET", "POST"}:
        fail(f"{path}.method", "is not supported")
    validate_headers(request["headers"], f"{path}.headers")
    if "formParameters" in request:
        validate_string_map(request["formParameters"], f"{path}.formParameters", MAX_FORM_PARAMETERS, MAX_TEMPLATE_LENGTH)
        if method == "GET" and request["formParameters"]:
            fail(f"{path}.formParameters", "GET requests cannot contain form parameters")
    if "signature" in request:
        validate_signature(request["signature"], f"{path}.signature")
    response_type = require_string(request["responseType"], f"{path}.responseType").upper()
    if response_type not in {"HTML", "JSON"}:
        fail(f"{path}.responseType", "is not supported")


def validate_bootstrap(value: Any, path: str) -> None:
    bootstrap = require_object(value, path)
    require_keys(
        bootstrap,
        {"tokenUrl", "tokenHeaders", "tokenFormParameters", "tokenRegex", "sessionUrlTemplate", "sessionHeaders"},
        set(),
        path,
    )
    validate_text(bootstrap["tokenUrl"], f"{path}.tokenUrl", MAX_TEMPLATE_LENGTH)
    validate_headers(bootstrap["tokenHeaders"], f"{path}.tokenHeaders")
    validate_string_map(bootstrap["tokenFormParameters"], f"{path}.tokenFormParameters", MAX_FORM_PARAMETERS, MAX_TEMPLATE_LENGTH)
    validate_regex(bootstrap["tokenRegex"], f"{path}.tokenRegex")
    validate_text(bootstrap["sessionUrlTemplate"], f"{path}.sessionUrlTemplate", MAX_TEMPLATE_LENGTH)
    validate_headers(bootstrap["sessionHeaders"], f"{path}.sessionHeaders")


def validate_share_preview(value: Any, path: str) -> None:
    preview = require_object(value, path)
    require_keys(
        preview,
        {"titleSelectors", "descriptionSelectors", "imageSelectors", "imageAllowedHosts"},
        {"request", "fallbackRequests", "bootstrap", "pageRequestHeaders", "imageRequestHeaders"},
        path,
    )
    validate_preview_selectors(preview["titleSelectors"], f"{path}.titleSelectors", True)
    validate_preview_selectors(preview["descriptionSelectors"], f"{path}.descriptionSelectors", False)
    validate_preview_selectors(preview["imageSelectors"], f"{path}.imageSelectors", False)
    validate_hosts(preview["imageAllowedHosts"], f"{path}.imageAllowedHosts")
    if "request" in preview:
        validate_preview_request(preview["request"], f"{path}.request")
    if "fallbackRequests" in preview:
        requests = require_array(preview["fallbackRequests"], f"{path}.fallbackRequests")
        if not 1 <= len(requests) <= MAX_PREVIEW_FALLBACK_REQUESTS:
            fail(f"{path}.fallbackRequests", f"must contain 1..{MAX_PREVIEW_FALLBACK_REQUESTS} requests")
        for index, request in enumerate(requests):
            validate_preview_request(request, f"{path}.fallbackRequests[{index}]")
    if "bootstrap" in preview:
        validate_bootstrap(preview["bootstrap"], f"{path}.bootstrap")
    if "pageRequestHeaders" in preview:
        validate_headers(preview["pageRequestHeaders"], f"{path}.pageRequestHeaders")
    if "imageRequestHeaders" in preview:
        validate_headers(preview["imageRequestHeaders"], f"{path}.imageRequestHeaders")


def validate_rule(value: Any, path: str) -> dict[str, Any]:
    rule = require_object(value, path)
    require_keys(
        rule,
        {
            "id",
            "version",
            "displayName",
            "source",
            "target",
            "shareTriggerSelectors",
            "sharePanelFingerprint",
            "copyLinkSelectors",
            "maxClickableParentDepth",
            "sharePanelTimeoutMs",
            "copySettleDelayMs",
            "clipboardExtraction",
            "redirectPolicy",
            "cleaningPolicy",
        },
        {"copyLinkScrollAnchorSelectors", "copyTriggerMode", "sharePreview"},
        path,
    )
    rule_id = require_string(rule["id"], f"{path}.id")
    if not 1 <= len(rule_id) <= MAX_ID_LENGTH or not TOKEN_PATTERN.fullmatch(rule_id):
        fail(f"{path}.id", "has an invalid rule id")
    version = require_int(rule["version"], f"{path}.version")
    if version <= 0:
        fail(f"{path}.version", "must be positive")
    validate_text(rule["displayName"], f"{path}.displayName", MAX_NAME_LENGTH)
    validate_source(rule["source"], f"{path}.source")
    validate_target(rule["target"], f"{path}.target")
    validate_selectors(rule["shareTriggerSelectors"], f"{path}.shareTriggerSelectors")
    validate_selectors(rule["sharePanelFingerprint"], f"{path}.sharePanelFingerprint")
    if "copyLinkScrollAnchorSelectors" in rule:
        validate_selectors(rule["copyLinkScrollAnchorSelectors"], f"{path}.copyLinkScrollAnchorSelectors")
    validate_selectors(rule["copyLinkSelectors"], f"{path}.copyLinkSelectors")
    if "copyTriggerMode" in rule:
        mode = require_string(rule["copyTriggerMode"], f"{path}.copyTriggerMode").upper()
        if mode not in {"AUTOMATIC", "USER_CONFIRMATION"}:
            fail(f"{path}.copyTriggerMode", "is not supported")
    clickable_depth = require_int(rule["maxClickableParentDepth"], f"{path}.maxClickableParentDepth")
    if not 0 <= clickable_depth <= MAX_CLICKABLE_PARENT_DEPTH:
        fail(f"{path}.maxClickableParentDepth", "is outside the supported range")
    panel_timeout = require_int(rule["sharePanelTimeoutMs"], f"{path}.sharePanelTimeoutMs")
    if not MIN_PANEL_TIMEOUT_MS <= panel_timeout <= MAX_PANEL_TIMEOUT_MS:
        fail(f"{path}.sharePanelTimeoutMs", "is outside the supported range")
    settle_delay = require_int(rule["copySettleDelayMs"], f"{path}.copySettleDelayMs")
    if not MIN_SETTLE_DELAY_MS <= settle_delay <= MAX_SETTLE_DELAY_MS:
        fail(f"{path}.copySettleDelayMs", "is outside the supported range")
    validate_clipboard(rule["clipboardExtraction"], f"{path}.clipboardExtraction")
    validate_redirect_policy(rule["redirectPolicy"], f"{path}.redirectPolicy")
    if "sharePreview" in rule:
        validate_share_preview(rule["sharePreview"], f"{path}.sharePreview")
    cleaning = require_object(rule["cleaningPolicy"], f"{path}.cleaningPolicy")
    require_keys(cleaning, {"removeExact", "removePrefixes", "forceKeep"}, set(), f"{path}.cleaningPolicy")
    validate_parameters(cleaning["removeExact"], f"{path}.cleaningPolicy.removeExact")
    validate_parameters(cleaning["removePrefixes"], f"{path}.cleaningPolicy.removePrefixes")
    validate_parameters(cleaning["forceKeep"], f"{path}.cleaningPolicy.forceKeep")
    return rule


def validate_bundle(bundle: dict[str, Any], path: str) -> list[dict[str, Any]]:
    require_keys(bundle, {"schemaVersion", "rules"}, set(), path)
    if require_int(bundle["schemaVersion"], f"{path}.schemaVersion") != 1:
        fail(f"{path}.schemaVersion", "only schemaVersion 1 is supported")
    rules = require_array(bundle["rules"], f"{path}.rules")
    if not 1 <= len(rules) <= MAX_RULES_PER_BUNDLE:
        fail(f"{path}.rules", f"must contain 1..{MAX_RULES_PER_BUNDLE} rules")
    return [validate_rule(rule, f"{path}.rules[{index}]") for index, rule in enumerate(rules)]


def build(rules_dir: Path, output: Path) -> None:
    files = sorted(rules_dir.glob("*.json"))
    if not files:
        fail(str(rules_dir), "no rule source files found")

    merged_rules: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path in files:
        rules = validate_bundle(load_json(path), path.name)
        for rule in rules:
            rule_id = rule["id"]
            if rule_id in seen_ids:
                fail(path.name, f"duplicate rule id across files: {rule_id}")
            seen_ids.add(rule_id)
            merged_rules.append(copy.deepcopy(rule))

    if len(merged_rules) > MAX_RULES_PER_BUNDLE:
        fail(str(rules_dir), f"combined bundle contains more than {MAX_RULES_PER_BUNDLE} rules")

    bundle = {"schemaVersion": 1, "rules": merged_rules}
    encoded = (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        fail(str(output), f"combined bundle is larger than {MAX_BUNDLE_BYTES} bytes")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)
    print(f"Validated {len(merged_rules)} rules from {len(files)} files -> {output} ({len(encoded)} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-dir", type=Path, default=Path("rules"))
    parser.add_argument("--output", type=Path, default=Path("build/rules.json"))
    args = parser.parse_args()
    try:
        build(args.rules_dir, args.output)
    except ValidationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
