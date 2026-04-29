import re
import logging

logger = logging.getLogger(__name__)


def sanitize_lucene(text):
    """
    Sanitizes a string for Lucene/Elasticsearch query_string.
    Escapes special characters that could be used for query injection.
    """
    if not text:
        return ""

    # List of Lucene special characters: + - && || ! ( ) { } [ ] ^ " ~ * ? : \ /
    # We escape them with a backslash
    special_chars = r'[+\-&|!(){}\[\]\^"~*?:\\]'
    return re.sub(special_chars, r"\\\g<0>", str(text))


def validate_numeric_id(val, name="ID"):
    """
    Validates that a value is numeric (int or numeric string).
    Returns the string representation of the integer.
    Raises ValueError if invalid.
    """
    try:
        return str(int(val))
    except (ValueError, TypeError):
        logger.error(
            f"Security Validation Failed: {name} must be numeric, got {type(val)}"
        )
        raise ValueError(f"Invalid {name}: must be numeric")


def sanitize_aql_string(text):
    """
    Sanitizes a string for QRadar AQL.
    Basically escapes single quotes which are used for string literals.
    """
    if not text:
        return ""
    return str(text).replace("'", "''")


def is_valid_fqdn(text):
    """
    Validates if a string is a valid FQDN.
    Must contain at least one dot and have a structure of [subdomain].domain.tld
    """
    if not text or not isinstance(text, str):
        return False
    # Regex for a basic FQDN check
    # 1. No dots at beginning or end
    # 2. At least one dot
    # 3. TLD must be at least 2 chars
    # 4. Length limits per segment (63) and total (253)
    if len(text) > 253:
        return False
    fqdn_regex = r"^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$"
    return bool(re.match(fqdn_regex, text))
