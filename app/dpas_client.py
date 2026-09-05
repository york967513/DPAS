import requests

from app.client_auth import create_client_signature
from app.protocol import create_authentication_request


class DPASClient:

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        salt: bytes,
        verify_tls: bool = True
    ):

        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.salt = salt
        self.verify_tls = verify_tls

        self.session_token = None

    # ==========================================
    # LOCAL CHALLENGE
    # ==========================================

    def create_local_authentication_request(
        self
    ) -> dict:

        return create_authentication_request(
            self.username
        )

    # ==========================================
    # SERVER CHALLENGE
    # ==========================================

    def request_challenge(self) -> dict:

        response = requests.post(
            f"{self.base_url}/auth/challenge",
            json={
                "username": self.username
            },
            verify=self.verify_tls,
            timeout=5
        )

        return response

    # ==========================================
    # SIGN CHALLENGE
    # ==========================================

    def create_signature(
        self,
        challenge: str
    ) -> str:

        return create_client_signature(
            self.username,
            self.password,
            self.salt,
            challenge
        )

    # ==========================================
    # AUTHENTICATE
    # ==========================================

    def authenticate(self) -> bool:

        # --------------------------------------
        # Request challenge from server
        # --------------------------------------

        response = self.request_challenge()

        if response.status_code != 200:
            self.clear_session()
            return False

        try:

            challenge_data = response.json()

            challenge = challenge_data["challenge"]

        except (
            ValueError,
            KeyError,
            TypeError
        ):

            self.clear_session()
            return False

        # --------------------------------------
        # Create Ed25519 signature
        # --------------------------------------

        try:

            signature = self.create_signature(
                challenge
            )

        except Exception:

            self.clear_session()
            return False

        # --------------------------------------
        # Send signature to server
        # --------------------------------------

        response = requests.post(
            f"{self.base_url}/auth/verify",
            json={
                "username": self.username,
                "challenge": challenge,
                "signature": signature
            },
            verify=self.verify_tls,
            timeout=5
        )

        if response.status_code != 200:

            self.clear_session()
            return False

        # --------------------------------------
        # Extract session token
        # --------------------------------------

        try:

            data = response.json()

            token = data["token"]

        except (
            ValueError,
            KeyError,
            TypeError
        ):

            self.clear_session()
            return False

        if not token:

            self.clear_session()
            return False

        self.set_session_token(
            token
        )

        return True

    # ==========================================
    # SESSION
    # ==========================================

    def set_session_token(
        self,
        token: str
    ):

        self.session_token = token

    def clear_session(self):

        self.session_token = None

    def is_authenticated(self) -> bool:

        if self.session_token is None:
            return False

        try:

            response = self.session()

            if response.status_code == 200:
                return True

            self.clear_session()

            return False

        except requests.RequestException:

            return False

    # ==========================================
    # AUTHORIZATION HEADER
    # ==========================================

    def authorization_header(self) -> dict:

        if self.session_token is None:

            raise RuntimeError(
                "Client is not authenticated"
            )

        return {
            "Authorization":
            f"Bearer {self.session_token}"
        }

    # ==========================================
    # HEALTH CHECK
    # ==========================================

    def health(self):

        return requests.get(
            f"{self.base_url}/health",
            verify=self.verify_tls,
            timeout=5
        )

    # ==========================================
    # CURRENT SESSION
    # ==========================================

    def session(self):

        response = requests.get(
            f"{self.base_url}/session",
            headers=self.authorization_header(),
            verify=self.verify_tls,
            timeout=5
        )

        return response

    # ==========================================
    # LOGOUT
    # ==========================================

    def logout(self):

        if self.session_token is None:
            return False

        try:

            response = requests.post(
                f"{self.base_url}/logout",
                headers=self.authorization_header(),
                verify=self.verify_tls,
                timeout=5
            )

        except requests.RequestException:

            return False

        if response.status_code == 200:

            self.clear_session()

            return True

        return False