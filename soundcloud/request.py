from urllib.parse import urlencode

import requests

import soundcloud

from . import hashconversions


def is_file_like(f):
    """Check to see if ```f``` has a ```read()``` method."""
    return hasattr(f, "read") and callable(f.read)


def extract_files_from_dict(d):
    """Return any file objects from the provided dict."""
    files = {}
    for key, value in d.items():
        if isinstance(value, dict):
            files[key] = extract_files_from_dict(value)
        elif is_file_like(value):
            files[key] = value
    return files


def remove_files_from_dict(d):
    """Return the provided dict with any file objects removed."""
    file_free = {}
    for key, value in d.items():
        if isinstance(value, dict):
            file_free[key] = remove_files_from_dict(value)
        elif not is_file_like(value):
            if hasattr(value, "__iter__"):
                file_free[key] = value
            else:
                if hasattr(value, "encode"):
                    file_free[key] = value.encode("utf-8")
                else:
                    file_free[key] = str(value)
    return file_free


def namespaced_query_string(d, prefix=""):
    """Transform a nested dict into a string with namespaced query params."""
    qs = {}
    prefixed = lambda k: prefix and f"{prefix}[{k}]" or k
    for key, value in d.items():
        if isinstance(value, dict):
            qs.update(namespaced_query_string(value, prefix=key))
        else:
            qs[prefixed(key)] = value
    return qs


def _extract_transport_kwargs(params):
    """Copy params, drop empty values, and split off transport/auth options.

    Returns (transport_kwargs, remaining_params) without mutating the input.
    """
    remaining = {k: v for k, v in params.items() if v is not None}

    transport = {"allow_redirects": remaining.pop("allow_redirects", True)}
    if remaining.get("verify_ssl") is False:
        transport["verify"] = False
    remaining.pop("verify_ssl", None)
    if "proxies" in remaining:
        transport["proxies"] = remaining.pop("proxies")
    if "timeout" in remaining:
        transport["timeout"] = remaining.pop("timeout")
    if "headers" in remaining:
        transport["headers"] = dict(remaining.pop("headers"))
    if "oauth_token" in remaining:
        transport.setdefault("headers", {})["Authorization"] = (
            "Bearer " + remaining.pop("oauth_token")
        )
    return transport, remaining


def _encode_body(params):
    """Encode params into (data, files) pairs for the request body."""
    params = hashconversions.to_params(params)
    files = namespaced_query_string(extract_files_from_dict(params))
    data = namespaced_query_string(remove_files_from_dict(params))
    return data, files


def make_request(method, url, params):
    """Make an HTTP request, formatting params as required."""
    transport, params = _extract_transport_kwargs(params)
    data, files = _encode_body(params)

    kwargs = {
        "allow_redirects": transport["allow_redirects"],
        "headers": {"User-Agent": soundcloud.USER_AGENT},
    }
    if "verify" in transport:
        kwargs["verify"] = transport["verify"]
    if "proxies" in transport:
        kwargs["proxies"] = transport["proxies"]
    if "timeout" in transport:
        kwargs["timeout"] = transport["timeout"]
    if "headers" in transport:
        kwargs["headers"].update(transport["headers"])

    request_func = getattr(requests, method, None)
    if request_func is None:
        raise TypeError(f"Unknown method: {method}")

    if method == "get":
        kwargs["headers"]["Accept"] = "application/json"
        qs = urlencode(data, doseq=True)
        if "?" in url:
            url = f"{url}&{qs}"
        else:
            url = f"{url}?{qs}"
        result = request_func(url, **kwargs)
    else:
        kwargs["data"] = data
        if files:
            kwargs["files"] = files
        result = request_func(url, **kwargs)

    # if redirects are disabled, don't raise for 301 / 302
    if result.status_code in (301, 302):
        if transport["allow_redirects"]:
            result.raise_for_status()
    else:
        result.raise_for_status()
    return result
