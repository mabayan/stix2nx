"""Input parsing for STIX bundles from various source formats."""

import json
import logging
import os
from glob import glob
from typing import Union

logger = logging.getLogger(__name__)


def parse_source(source: Union[str, list[str], list[dict]]) -> list[dict]:
    """Parse a STIX source into a list of bundle dicts.

    Args:
        source: One of:
            - str: file path (.json) or directory path
            - list[str]: list of JSON strings, each a STIX bundle
            - list[dict]: list of already-parsed STIX bundle dicts

    Returns:
        List of parsed STIX bundle dicts.

    Raises:
        ValueError: If the source format is invalid or JSON parsing fails.
        FileNotFoundError: If a file or directory path doesn't exist.
    """
    if isinstance(source, str):
        return _parse_string_source(source)
    elif isinstance(source, list):
        return _parse_list_source(source)
    else:
        raise ValueError(
            f"source must be a str (file/directory path) or list (JSON strings or dicts), "
            f"got {type(source).__name__}"
        )


def _parse_string_source(source: str) -> list[dict]:
    """Parse a string source (file path or directory path)."""
    if os.path.isdir(source):
        return _parse_directory(source)
    elif source.endswith(".json") or os.path.isfile(source):
        return [_parse_file(source)]
    else:
        raise ValueError(
            f"String source must be a path to a .json file or a directory, "
            f"got: {source!r}"
        )


def _parse_directory(dir_path: str) -> list[dict]:
    """Parse all .json files in a directory (non-recursive)."""
    pattern = os.path.join(dir_path, "*.json")
    files = sorted(glob(pattern))
    if not files:
        logger.warning(f"No .json files found in directory: {dir_path}")
        return []
    bundles = []
    for f in files:
        bundles.append(_parse_file(f))
    return bundles


def _parse_file(file_path: str) -> dict:
    """Parse a single JSON file into a bundle dict."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"STIX bundle file not found: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON from {file_path}: {e}") from e
    if not isinstance(bundle, dict):
        raise ValueError(f"Expected a JSON object (dict) in {file_path}, got {type(bundle).__name__}")
    return bundle


def _parse_list_source(source: list) -> list[dict]:
    """Parse a list source (JSON strings or dicts)."""
    if not source:
        return []

    first = source[0]
    if isinstance(first, dict):
        return list(source)
    elif isinstance(first, str):
        bundles = []
        for i, s in enumerate(source):
            if not isinstance(s, str):
                raise ValueError(
                    f"Mixed types in source list: expected all str, "
                    f"got {type(s).__name__} at index {i}"
                )
            try:
                bundle = json.loads(s)
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse JSON string at index {i}: {e}") from e
            if not isinstance(bundle, dict):
                raise ValueError(
                    f"Expected JSON object (dict) at index {i}, got {type(bundle).__name__}"
                )
            bundles.append(bundle)
        return bundles
    else:
        raise ValueError(
            f"List elements must be str (JSON) or dict (parsed bundles), "
            f"got {type(first).__name__}"
        )
