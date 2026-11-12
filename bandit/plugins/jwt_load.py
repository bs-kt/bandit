#
# SPDX-License-Identifier: Apache-2.0
r"""
=====================================================
B555: Insecure JWT  - Test for insecure JWT configurations
=====================================================

This plugin checks common security misconfigurations associated with JWTs.

:Example:

.. code-block:: none

    >> Issue: Inadequate Encryption Strength
       Severity: High   Confidence: High
       CWE: CWE-326 (https://cwe.mitre.org/data/definitions/326.html)
       More Info: # https://bandit.readthedocs.io/en/1.7.5/plugins/b113_trojansource.html need to update website
       with this plugin
       Location: examples/insecure-jwt-configuration.py

    >> Issue: Improper Verification of Cryptographic Signature
       Severity: Medium   Confidence: Medium
       CWE: CWE-347 (https://cwe.mitre.org/data/definitions/347.html)
       More Info: # https://bandit.readthedocs.io/en/1.7.5/plugins/b113_trojansource.html need to update website
       with this plugin
       Location: examples/insecure-jwt-configuration.py

    >> Issue: Use of Hard-coded credentials
       Severity: High   Confidence: High
       CWE: CWE-798 (https://cwe.mitre.org/data/definitions/798.html)
       More Info: # https://bandit.readthedocs.io/en/1.7.5/plugins/b113_trojansource.html need to update website
       with this plugin
       Location: examples/insecure-jwt-configuration.py

.. seealso::

 - https://www.cve.org/CVERecord?id=CVE-2022-39227

.. versionadded:: 1.9.5

"""
import enum
import re
from typing import Optional
from dataclasses import dataclass
from jwt import PyJWK
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import bandit
from bandit.core import issue
from bandit.core import test_properties as test
import ast

class JWTConfigStatus(enum.Enum):
    OKAY = 0
    WEAK = 1
    UNKNOWN = 2 # Does not have any significance in the code yet. Used for PyJWK instances in encoding or decoding methods

@dataclass
class JWTAnalysisResult:
    status: JWTConfigStatus = JWTConfigStatus.UNKNOWN
    message: str = ""
    severity: Optional[int] = None
    confidence: Optional[str] = None
    cwe: Optional[issue.Cwe] = None
    is_key_secret: bool = True

    def to_bandit_issue(self, lineno) -> Optional[bandit.Issue]:
        """
        Converts the data to a bandit.Issue if the configuration is detected to be weak.

        :param lineno: The line number of the context.
        :return: A bandit.Issue if the configuration is weak.
        """
        if not self.is_key_secret:
            self.message = f"(WARNING: CWE-798 (https://cwe.mitre.org/data/definitions/798.html), KEY IS HARDCODED) {self.message}"

        if self.status == JWTConfigStatus.WEAK:
            return bandit.Issue(
                severity=self.severity,
                cwe=self.cwe,
                confidence=self.confidence,
                text=self.message,
                lineno=lineno,
            )
        return None

    def populate_results(self, status, message, severity, confidence, cwe):
        """
        Populates the results of the dataclass to later be converted to a bandit.Issue

        :param status: The status of the analysis.
        :param message: The message of the issue.
        :param severity: The severity level according to the CWE and code detection
        :param confidence: The confidence level according to the CWE and code detection
        :param cwe: The assigned CWE
        """
        self.status = status
        self.message = message
        self.severity = severity
        self.confidence = confidence
        self.cwe = cwe

def gen_config(name):
    """
    Generates the config for this plugin.

    :param name: The configuration name
    :return: The configuration dictionary for this plugin.
    """
    if name == "jwt_security":
        return {
            "weak_jwt_keys": [  # definitely not as exhaustive as seclists, but useful for testing purposes right now
                "secret",
                "password",
                "123456",
                "password123",
                "changeme",
                "your-secret-key",
                "my-secret-key",
                "jwt-secret",
                "supersecret",
                "test-secret",
                "development-secret",
            ],
            "key_requirements": { # in bytes
                "generic_baseline": {
                    "min_bytes": 32
                }  # This is if an explicit algorithm cannot be determined.
            },
            "weak_key_patterns": [
                r"^[0-9]+$", # numeric only
                r"^[a-zA-Z]+$",# alphabet only
                r"^(.)\1{7,}$"  # characters repeated more than 7 times
            ],
            "jwt_methods": [
                "jwt.encode",
                "jwt.decode",
                "jwt.decode_complete"
            ]
        }
    return None

def _check_key_family_security_weakness(key, algorithm, analyze_jwt_result: JWTAnalysisResult, is_encoding = True):
    """
    Checks key strength for signature algorithms as well as matching configurations.

    :param key: The key to check
    :param algorithm: The name of the algorithm
    :param analyze_jwt_result: the JWTAnalysisResult dataclass instance
    :param is_encoding: determines whether the key is being used to encode or not
    :return: Returns a bandit.Issue if there is a problem with the configuration otherwise nothing
    """
    ec_mapping = {
        "ES256": "secp256r1",
        "ES384": "secp384r1",
        "ES512": "secp521r1",
        "ES256K": "secp256k1",
    }
    if is_encoding:
        if isinstance(key, RSAPrivateKey) or isinstance(key, EllipticCurvePrivateKey):
            public_key = key.public_key()
            # Need to check both public and private keys
            if isinstance(key, RSAPrivateKey):
                if public_key.key_size < 2048:
                    analyze_jwt_result.populate_results(
                        status=JWTConfigStatus.WEAK,
                        message="RSA modulus is not strong enough! Recommended minimum is 2048 bits!",
                        severity=bandit.HIGH,
                        confidence=bandit.HIGH,
                        cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
                    )

            else:
                expected_curve = ec_mapping.get(algorithm, None)
                if expected_curve is None or expected_curve != public_key.curve.name:
                    analyze_jwt_result.populate_results(
                        status=JWTConfigStatus.WEAK,
                        message="Expected elliptic curve does not match!",
                        severity=bandit.HIGH,
                        confidence=bandit.HIGH,
                        cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
                    )

        else:
            public_key = key.public_key()
            num_bytes = 32 if isinstance(key, Ed25519PrivateKey) else 2048
            if len(public_key.public_bytes_raw) != num_bytes:
                analyze_jwt_result.populate_results(
                    status=JWTConfigStatus.WEAK,
                    message="Number of bytes does not match!",
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
                )
    else:
        if isinstance(key, RSAPublicKey) or isinstance(key, EllipticCurvePublicKey):
            if isinstance(key, RSAPublicKey):
                if key.key_size < 2048:
                    analyze_jwt_result.populate_results(
                        status=JWTConfigStatus.WEAK,
                        message="RSA modulus is not strong enough! Recommended minimum is 2048 bits!",
                        severity=bandit.HIGH,
                        confidence=bandit.HIGH,
                        cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
                    )
            else:
                expected_curve = ec_mapping.get(algorithm, None)
                if expected_curve is None or expected_curve != key.curve.name:
                    analyze_jwt_result.populate_results(
                        status=JWTConfigStatus.WEAK,
                        message="Expected elliptic curve does not match!",
                        severity=bandit.HIGH,
                        confidence=bandit.HIGH,
                        cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
                    )
        else:
            num_bytes = 32 if isinstance(key, Ed25519PublicKey) else 2048
            if len(key.public_bytes_raw()) != num_bytes:
                analyze_jwt_result.populate_results(
                    status=JWTConfigStatus.WEAK,
                    message="Number of bytes does not match!",
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
                )

def _check_bad_key_string(config, key: str, analyze_jwt_result: JWTAnalysisResult):
    """
    Checks if a key given as a string is weak according to its length, pattern, or if it is a commonly used weak
    key.

    :param config: The config from this plugin
    :param key: The key to check
    :param analyze_jwt_result: the JWTAnalysisResult dataclass instance
    """
    if key in config["weak_jwt_keys"]:
        analyze_jwt_result.populate_results(
            status=JWTConfigStatus.WEAK,
            message="Key configured found in weak key list!",
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
        )
        return

    # Check other weak configurations such as weak lengths and configuration
    encoded_byte_key = key.encode("utf-8")
    if len(encoded_byte_key) < config["key_requirements"]["generic_baseline"]["min_bytes"]:
        analyze_jwt_result.populate_results(
            status=JWTConfigStatus.WEAK,
            message="Key configured is not long enough!",
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
        )
        return

    for pattern in config["weak_key_patterns"]:
        if re.search(pattern, key):
            analyze_jwt_result.populate_results(
                status=JWTConfigStatus.WEAK,
                message="Key configuration found to be a weak pattern!",
                severity=bandit.HIGH,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH
            )
            return

    analyze_jwt_result.status = JWTConfigStatus.OKAY

def _check_if_key_is_weak(config, key, algorithm, analyze_jwt_result: JWTAnalysisResult, is_encoding = True):
    """
    Central function interface to checking key strength.

    :param config: The config from this plugin.
    :param key: The key to check
    :param algorithm: The signature algorithm being used
    :param analyze_jwt_result: The JWTAnalysisResult dataclass instance
    :param is_encoding: Whether the key is being used for encoding or decoding
    """
    if isinstance(key, str):
        _check_bad_key_string(config, key, analyze_jwt_result)
    elif isinstance(key, bytes):
        decoded_key = key.decode("utf-8")
        _check_bad_key_string(config, decoded_key, analyze_jwt_result)
    elif isinstance(key, PyJWK):
         analyze_jwt_result.status = JWTConfigStatus.UNKNOWN
    else: # check type AllowedPrivateKeys | AllowedPublicKeys
        _check_key_family_security_weakness(key, algorithm, analyze_jwt_result, is_encoding)


def _parse_file_ast_tree(context, key_name_node, analyze_jwt_result: JWTAnalysisResult):
    """
        Parses the file that is being processed into an AST tree to find hardcoded values. Note that this
        will not happen if the algorithm is set to None.

        :param context: The context from this plugin call.
        :param key_name_node: The key node
        :param analyze_jwt_result: The JWTAnalysisResult dataclass instance
    """
    file_data = context.file_data
    file_data.seek(0)
    file_bytes = file_data.read()
    source_tree = ast.parse(file_bytes)
    key_value = None

    for node in ast.walk(source_tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant):
                if key_name_node.id in list(map(lambda name_object: name_object.id, node.targets)):
                    analyze_jwt_result.is_key_secret = False
                    key_value = str(node.value.value)
    return key_value

def _get_argument(context, value: str, arg_position: int):
    """
    Small helper that will help retrieve the key or algorithm from encoding and decoding.
    The logic is as follows:
        1. Read the keyword argument literal
        2. If that fails, try reading the literal as a positional argument
        3. If that fails, then the keyword or positional argument is a variable. Parse it in resolution (caller)
           as this will be an AST node.

    :param context: The context from this plugin
    :param value: The name of the argument in the method
    :param arg_position: a non-negative integer representing the position in the argument list in the method (from 0)
    :return: The correct parsed value from the encoding or decoding method
    """
    argument = context.get_call_arg_value(value)
    if argument is None:
        # Get the node
        argument = context.node.args[arg_position]

    return argument

def _resolve_argument(context, value: str, arg_position: int, analyze_jwt_result: JWTAnalysisResult):
    """
    Resolves the value type inside the encoding or decoding methods.

    :param context: The context from this plugin
    :param value: The name of the argument
    :param arg_position: a non-negative integer representing the position in the argument list (from 0)
    :param analyze_jwt_result: The JWTAnalysisResult dataclass instance
    :return: The correct parsed value from the encoding or decoding methods
    """
    argument = _get_argument(context, value, arg_position)

    if isinstance(argument, str):
        if value == "key":
            analyze_jwt_result.is_key_secret = False

    elif isinstance(argument, ast.Name):
        # Parse the file AST tree and get the actual value of the key and return it. Also mark if on the way if the value
        # is hardcoded.
        if value == "key":
            parse = _parse_file_ast_tree(context, argument, analyze_jwt_result)
            if parse is not None:
                argument = parse
            analyze_jwt_result.is_key_secret = False
    return argument

def _analyze_jwt(context, config) -> Optional[bandit.Issue]:
    """
    Analyzes the JWT configuration obtained from Bandit's Call check.

    :param context: The context from this plugin
    :param config: The config from this plugin
    :return: A bandit.Issue if a security misconfiguration is noticed, None otherwise
    """
    analyze_jwt_result = JWTAnalysisResult()
    algorithm = _resolve_argument(context, "algorithm", 2, analyze_jwt_result)
    lineno = context.get_lineno_for_call_arg("algorithm")
    if algorithm == "None":
        analyze_jwt_result.populate_results(
            status=JWTConfigStatus.WEAK,
            message="Use of None as the signing algorithm in PyJWT falls back to the 'alg' parameter in header,"
                 " which may decrease integrity as header's \"alg\" value may also be none. Don't rely on JWT metadata and instead rely on explicit security configurations",
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.IMPROPER_VERIFICATION_CRYPTOGRAPHIC_SIGNATURE
        )
        # Don't need to save key here, just reusing some logic to mark if the key is hardcoded
        _ = _resolve_argument(context, "key", 1, analyze_jwt_result)
    else:
        # Check for hardcoded sensitive values, such as keys and check for a lack of sufficient entropy
        key = _resolve_argument(context, "key", 1, analyze_jwt_result)
        lineno = context.get_lineno_for_call_arg("key")
        _check_if_key_is_weak(config, key, algorithm, analyze_jwt_result, context.call_function_name_qual == "jwt.encode")

    if analyze_jwt_result.status == JWTConfigStatus.WEAK:
        return analyze_jwt_result.to_bandit_issue(lineno)

    return None

@test.checks("Call")
@test.test_id("B555")
@test.takes_config("jwt_security")
def get_jwt(context, config) -> Optional[bandit.Issue]:
    """
    Retrieves the JWT configurations from encoding and decoding methods.

    :param context: The context from this plugin
    :param config: The config from this plugin
    :return: A bandit.Issue if a security misconfiguration is noticed from JWT encoding and decoding methods from the analysis, None otherwise
    """
    if config is not None:
        if context.call_function_name_qual in config["jwt_methods"]:
            result = _analyze_jwt(context, config)
            return result

    return None