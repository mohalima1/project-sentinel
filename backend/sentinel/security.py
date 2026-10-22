import hashlib
import hmac
import secrets


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=5)
    return f"scrypt$16384$8$5${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    if len(password) > 128:
        return False
    try:
        parts = encoded.split("$")
        if len(parts) == 3:
            algorithm, salt, expected = parts
            parallelism = 1
        elif len(parts) == 6 and parts[1:4] == ["16384", "8", "5"]:
            algorithm, _, _, _, salt, expected = parts
            parallelism = 5
        else:
            return False
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt), n=16384, r=8, p=parallelism
        )
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
