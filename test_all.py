import json
import time
from unittest.mock import Mock, call

import pytest
from requests import Response, Session

from .lansforsakringar import Lansforsakringar, LansforsakringarBankIDLogin


@pytest.fixture
def mock_personnummer() -> str:
    return "201701012393"  # https://www.dataportal.se/sv/datasets/6_67959/testpersonnummer


def read_test_response_from_file(filename: str, status_code: int = 200) -> Mock:
    with open(f"test_data/{filename}", "r") as f:
        return mock_response(f.read(), status_code)


@pytest.fixture
def start_auth_data() -> dict[str, str]:
    return {
        "qrData": "bankid.718bd0d5-a47e-11f0-bfb4-d85ed3a2d75f.0.4bc9b199e772162b90fe406b109472b854c87eaedbdfd63f7061bb2700cacb94"
    }


@pytest.fixture
def collect_auth_step_1() -> dict[str, str]:
    return {
        "qrData": "bankid.15b23b0c-a484-11f0-b4d3-d85ed3a2d75f.0.4bc9b199e772162b90fe406b109472b854c87eaedbdfd63f7061bb2700cacb94",
        "status": "pending",
        "hintCode": "outstandingTransaction",
        "resultCode": "OUTSTANDING_TRANSACTION",
    }


@pytest.fixture
def collect_auth_step_2() -> dict[str, str]:
    return {"status": "pending", "hintCode": "userSign", "resultCode": "USER_SIGN"}


@pytest.fixture
def collect_auth_step_3() -> dict[str, str]:
    return {"status": "complete", "resultCode": "COMPLETE", "expiresIn": 0}


@pytest.fixture
def mock_response(response_data: str | dict, status_code=200):
    mock_response = Mock(Response)
    if isinstance(response_data, dict):
        mock_response.text = json.dumps(response_data)
        mock_response.json.return_value = response_data
    else:
        mock_response.text = response_data
        mock_response.json.return_value = json.loads(response_data)
    mock_response.status_code = status_code
    return mock_response


@pytest.fixture
def mock_post(monkeypatch, mock_response):
    mocked_post = Mock(return_value=mock_response)
    monkeypatch.setattr(Session, "post", mocked_post)
    return mocked_post


class TestLansforsakringarBankIDLogin:
    @pytest.mark.parametrize("response_data", [pytest.lazy_fixture("start_auth_data")])
    def test_start_auth(self, mock_post, start_auth_data, mock_personnummer) -> None:
        login = LansforsakringarBankIDLogin(mock_personnummer)
        assert login.start_auth() == start_auth_data["qrData"]

        mock_post.assert_called_once_with(
            LansforsakringarBankIDLogin.BASE_URL + "/security/login/security-login/v2/start-auth",
            json={"useQRCode": True, "authType": "BANKID", "isForCompany": False},
        )

    def test_collect_auth(
        self,
        monkeypatch,
        start_auth_data,
        mock_personnummer,
        collect_auth_step_1,
        collect_auth_step_2,
        collect_auth_step_3,
    ):
        response_1 = Mock(Response, **{"json.return_value": collect_auth_step_1})
        response_2 = Mock(Response, **{"json.return_value": collect_auth_step_2})
        response_3 = Mock(Response, **{"json.return_value": collect_auth_step_3})
        mocked_get = Mock(side_effect=[response_1, response_2, response_3])
        monkeypatch.setattr(Session, "get", mocked_get)
        monkeypatch.setattr(time, "sleep", lambda x: None)
        login = LansforsakringarBankIDLogin(mock_personnummer)
        login.collect_auth(start_auth_data["qrData"])

        get_call = call(LansforsakringarBankIDLogin.BASE_URL + "/security/login/security-login/v2/collect-auth")
        assert mocked_get.call_count == 3
        mocked_get.assert_has_calls([get_call] * 3)


class TestLansforsakringar:
    @pytest.mark.parametrize("response_data", [open("test_data/getaccounts.txt", "r").read()])
    def test_get_accounts(self, mock_post, mock_personnummer) -> None:
        lans = Lansforsakringar(mock_personnummer)
        accounts = lans.get_accounts()
        mock_post.assert_called_once_with(
            Lansforsakringar.BASE_URL + "/im/json/overview/getaccounts",
            json={
                "customerId": mock_personnummer,
                "responseControl": {"filter": {"includes": ["ALL"]}},
            },
            headers={
                "Content-type": "application/json",
                "Accept": "application/json",
                "CSRFToken": None,
            },
        )
        assert isinstance(accounts, dict)
        # TODO: sometimes the account number is doubly string quoted
        assert list(accounts.keys()) == ["'50850045845'", "50850045846"]

        account_1 = accounts["'50850045845'"]
        assert account_1["uncertainClaim"] is False
        assert account_1["creditAllowed"] is False
        assert account_1["name"] == "Privatkonto"
        assert account_1["currentBalance"] == 1234.32
        assert account_1["availableBalance"] == 1234.32
        assert account_1["type"] == "PRIMARY_ACCOUNT_OWNER"

        account_2 = accounts["50850045846"]
        assert account_2["uncertainClaim"] is False
        assert account_2["creditAllowed"] is False
        assert account_2["name"] == "Sparkonto"
        assert account_2["currentBalance"] == 12345.33
        assert account_2["availableBalance"] == 12345.33
        assert account_2["type"] == "PRIMARY_ACCOUNT_OWNER"
