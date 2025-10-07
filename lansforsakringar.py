import json
import logging
import os
import re
import time
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import pyqrcode
import requests

logging.basicConfig()
_logger = logging.getLogger(__name__)
_logger.setLevel(logging.ERROR)
ch = logging.StreamHandler()
_logger.addHandler(ch)

requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.ERROR)
requests_log.propagate = True

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0"


class LansforsakringarError(Exception):
    pass


class LansforsakringarBankIDLogin:
    """
    Lansforsakringar does not support password based login anymore
    So we need to support BankID based login.
    This is not easy, as we need a human in the loop operating the app
    """

    BASE_URL = "https://api.lansforsakringar.se"
    CLIENT_ID = "LFAB-59IjjFXwGDTAB3K1uRHp9qAp"
    HEADERS = {
        "User-Agent": USER_AGENT,
        "Authorization": f'Atmosphere atmosphere_app_id="{CLIENT_ID}"',
        "Content-Type": "application/json;charset=UTF-8",
        "Accept": "application/json",
    }

    def __init__(self, personnummer):
        self.personnummer = personnummer
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)

    def start_auth(self) -> None:
        url = self.BASE_URL + "/security/login/security-login/v2/start-auth"
        req = self.session.post(url, json={"useQRCode": True, "authType": "BANKID", "isForCompany": False})
        # sets cookie sessionId
        qr_data = req.json()["qrData"]
        print(self.get_qr_terminal(qr_data))
        print("Please scan this QR code.")
        return qr_data

    def collect_auth(self, initial_qr_data: str) -> None:
        url = self.BASE_URL + "/security/login/security-login/v2/collect-auth"
        wait_ended = False
        last_qr_data = initial_qr_data
        while not wait_ended:
            req = self.session.get(url)
            data = req.json()
            _logger.info(data)
            if "qrData" in data.keys():
                if data["qrData"] != last_qr_data:
                    print(self.get_qr_terminal(data["qrData"]))
                    print("Please scan this QR code.")
                    last_qr_data = data["qrData"]
            elif data["status"] == "pending":
                print("Please authenticate in the BankID app...")
            elif data["status"] == "complete":
                # Deletes sessionId cookie
                # Sets a new cookie APIP_TOKEN on .lansforsakringar.se, so we just return the whole cookie jar
                print("Login successful.")
                wait_ended = True
            else:
                print(f"Unkown message: {data['status']}")
            time.sleep(3)

    def get_qr_terminal(self, qr_data: str) -> str:
        """
        Get Linux terminal printout of QR Code
        """
        bankidqr = pyqrcode.create(qr_data)
        return bankidqr.terminal()

    def get_cookie(self) -> requests.cookies.RequestsCookieJar:
        inital_qr = self.start_auth()
        self.collect_auth(inital_qr)
        return self.session.cookies


class Lansforsakringar:
    BASE_URL = "https://secure246.lansforsakringar.se"
    HEADERS = {"User-Agent": USER_AGENT}

    def __init__(self, personal_identity_number: str):
        self.personal_identity_number = personal_identity_number
        self.accounts = {}

        self.json_token = None

        # Setup requests session
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)

    def _save_token_and_cookies(self) -> None:
        with open("lans_token.txt", "w") as file:
            file.write(self.json_token)

        with open("lans_url_token.txt", "w") as file:
            file.write(self.url_token)

        with open("lans_cookies.txt", "w") as file:
            file.write(json.dumps(self.session.cookies.items()))

    def _load_token_and_cookies(self) -> None:
        try:
            with open("lans_token.txt", "r") as file:
                token = file.read().replace("\n", "")
                self.json_token = token

            with open("lans_url_token.txt", "r") as file:
                self.url_token = file.read().replace("\n", "")

            with open("lans_cookies.txt", "r") as file:
                self.session.cookies.update(json.loads(file.read()))
        except FileNotFoundError:
            pass

    def check_token_and_cookies(self) -> bool:
        self._load_token_and_cookies()

        verify = True

        override_ca_bundle = os.getenv("OVERRIDE_CA_BUNDLE")
        if override_ca_bundle:
            verify = override_ca_bundle
        req = self.session.get(self.BASE_URL + "/im/login/privat", verify=verify)
        url = urlparse(req.url)
        if url.path != "/im/im/csw.jsf":
            print(f"Login failed, now on {url.path}")
            # request failed, unset data
            self.json_token = None
            self.session.cookies.clear()
            return False

        # store url token
        self.url_token = parse_qs(url.query)["_token"]

        return True

    def _parse_json_token(self, body: str) -> str:
        """Parse the JSON token from body."""

        token_match = re.search(r"jsontoken=([\w-]+)", body)
        return token_match.group(1)

    def _parse_token(self, body: str, use_cache: bool) -> None:
        """Parse and save tokens from body."""
        old_json_token = self.json_token
        self.json_token = self._parse_json_token(body)
        if use_cache:
            self._save_token_and_cookies()

        _logger.debug(f"JSON token set to: {self.json_token} (Old: {old_json_token})")

    def _parse_account_transactions(self, decoded: dict) -> dict:
        """Parse and return list of all account transactions."""

        transactions = []

        try:
            if "historicalTransactions" in decoded["response"]["transactions"]:
                for row in decoded["response"]["transactions"]["historicalTransactions"]:
                    transaction = {
                        "bookKeepingDate": row["bookKeepingDate"],
                        "transactionDate": row["transactionDate"],
                        "type": row["transactionType"],
                        "text": row["transactionText"],
                        "amount": row["amount"],
                        "comment": row["comment"],
                    }
                    transactions.append(transaction)
            if "upcomingTransactions" in decoded["response"]["transactions"]:
                for row in decoded["response"]["transactions"]["upcomingTransactions"]:
                    transaction = {
                        "transactionDate": row["transactionDate"],
                        "type": row["transactionType"],
                        "text": row["transactionText"],
                        "amount": row["amount"],
                        "comment": row["comment"],
                    }
                    transactions.append(transaction)
            return transactions
        except KeyError as e:
            print(f"Error: {e}, JSON: {decoded}")

    def login(self, cookie_jar: requests.cookies.RequestsCookieJar, use_cache=False) -> bool:
        """
        Login to the web bank
        cookie_jar: A CookieJar from the LansforsakringarBankIDLogin
        use_cache: Store token and cookies to disk. Beware that anyone with read access to those files can
        send requests as you until they time out
        """

        verify = True

        override_ca_bundle = os.getenv("OVERRIDE_CA_BUNDLE")
        if override_ca_bundle:
            verify = override_ca_bundle
        self.session.cookies = cookie_jar
        resp = self.session.get(self.BASE_URL + "/im/login/privat", verify=verify)
        url = urlparse(resp.url)
        self.url_token = parse_qs(url.query)["_token"][0]
        _logger.debug(f"URL token is {self.url_token}")

        self._parse_token(resp.text, use_cache)

        return True

    def get_accounts(self) -> bool | dict:
        """Fetch bank accounts by using json.

        This uses the same json api URL that the browser does when logged in.
        It also need to send the CSRFToken (JSON token) in order to work.
        """

        data = {
            "customerId": self.personal_identity_number,
            "responseControl": {"filter": {"includes": ["ALL"]}},
        }

        headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
            "CSRFToken": self.json_token,
        }
        path = "/im/json/overview/getaccounts"
        req = self.session.post(self.BASE_URL + path, json=data, headers=headers)

        _logger.debug(f"Transaction request response code {req.status_code}.")

        try:
            response = req.json()
            for account in response["response"]["accounts"]:
                self.accounts[account["number"]] = account
                del self.accounts[account["number"]]["number"]

            return self.accounts
        except json.decoder.JSONDecodeError:
            _logger.error("JSON Decode error on get_accounts.")
            return False
        except KeyError:
            _logger.error("KeyError on account loading.")
            return False

    def get_account_transactions(
        self,
        account_number: str,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
    ) -> list:
        """Fetch and return account transactions for account_number."""
        if from_date is not None:
            from_date_str = from_date.strftime("%Y-%m-%d")
        else:
            from_date_str = ""
        if to_date is not None:
            to_date_str = to_date.strftime("%Y-%m-%d")
        else:
            to_date_str = ""
        pageNumber = 0
        moreExist = True
        transactions = []

        while moreExist:
            data = {
                "accountNumber": account_number,
                "currentPageNumber": pageNumber,
                "searchCriterion": {
                    "fromDate": from_date_str,
                    "toDate": to_date_str,
                    "fromAmount": "",
                    "toAmount": "",
                },
            }

            headers = {
                "Content-type": "application/json",
                "Accept": "application/json",
                "CSRFToken": self.json_token,
            }
            path = "/im/json/account/getaccounttransactions"
            req = self.session.post(self.BASE_URL + path, json=data, headers=headers)

            _logger.debug(f"Transaction request response code {req.status_code}.")
            _logger.debug(req.text)

            # Parse transactions
            decoded = req.json()

            moreExist = decoded["response"]["transactions"]["moreExist"]
            pageNumber += 1

            transactions += self._parse_account_transactions(decoded)
            _logger.debug(transactions)

        return transactions

    def get_cards(self) -> dict:
        data = {
            "customerId": self.personal_identity_number,
            "responseControl": {
                "profile": {
                    "customerId": self.personal_identity_number,
                    "profileType": "CUSTOMER",
                    "subjectUserId": None,
                },
                "content": {
                    "includes": [
                        {"include": "AVAILABLE_BALANCE"},
                        {"include": "DEBIT_ACCOUNT_NAME"},
                    ]
                },
                "filter": {"includes": [{"cardStatus": ["ACTIVE", "TEMPORARY_BLOCKED", "NOT_ACTIVATED"]}]},
            },
        }

        headers = {"Content-type": "application/json", "Accept": "*/*"}
        path = "/es/card/getcards/3.1"
        req = self.session.post(self.BASE_URL + path, json=data, headers=headers)

        data = req.json()
        return data["response"]["cards"]
