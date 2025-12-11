from enum import Enum

class ErrorCode(Enum):
    NETWORK_ERROR = "E101"
    PARSE_ERROR = "E102"
    DATABASE_ERROR = "E103"
    CONFIG_ERROR = "E104"
    UNKNOWN_ERROR = "E999"

class CollectorError(Exception):
    """Base class for exceptions in this module."""
    def __init__(self, message, code=ErrorCode.UNKNOWN_ERROR):
        self.message = message
        self.code = code
        super().__init__(f"[{code.value}] {message}")

class NetworkError(CollectorError):
    def __init__(self, message):
        super().__init__(message, ErrorCode.NETWORK_ERROR)

class ParseError(CollectorError):
    def __init__(self, message):
        super().__init__(message, ErrorCode.PARSE_ERROR)

class ConfigError(CollectorError):
    def __init__(self, message):
        super().__init__(message, ErrorCode.CONFIG_ERROR)
