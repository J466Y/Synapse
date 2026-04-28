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
    return re.sub(special_chars, r'\\\g<0>', str(text))

def validate_numeric_id(val, name="ID"):
    """
    Validates that a value is numeric (int or numeric string).
    Returns the string representation of the integer.
    Raises ValueError if invalid.
    """
    try:
        return str(int(val))
    except (ValueError, TypeError):
        logger.error(f"Security Validation Failed: {name} must be numeric, got {type(val)}")
        raise ValueError(f"Invalid {name}: must be numeric")

def sanitize_aql_string(text):
    """
    Sanitizes a string for QRadar AQL.
    Basically escapes single quotes which are used for string literals.
    """
    if not text:
        return ""
    return str(text).replace("'", "''")
