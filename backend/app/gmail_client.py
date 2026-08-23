"""Typed REST client for Gmail OAuth, mailbox history, and labels."""

from __future__ import annotations

from urllib.parse import urlencode

import httpx

from .config import settings
from .models import (
    EmailMonitoringMode,
    GmailAttachmentData,
    GmailHistoryResponse,
    GmailLabel,
    GmailLabelList,
    GmailMessage,
    GmailMessageList,
    GmailProfile,
    GmailTokenResponse,
    GmailWatchResponse,
)

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
API_URL = "https://gmail.googleapis.com/gmail/v1"


class GmailClient:
    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._client = httpx.Client(timeout=30, transport=transport)

    def authorization_url(self, state: str, challenge: str) -> str:
        params = {
            "client_id": settings.gmail_oauth_client_id,
            "redirect_uri": settings.gmail_oauth_redirect_uri,
            "response_type": "code",
            "scope": GMAIL_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    def exchange_code(self, code: str, verifier: str) -> GmailTokenResponse:
        response = self._client.post(
            TOKEN_URL,
            data={
                "client_id": settings.gmail_oauth_client_id,
                "client_secret": settings.gmail_oauth_client_secret,
                "code": code,
                "code_verifier": verifier,
                "grant_type": "authorization_code",
                "redirect_uri": settings.gmail_oauth_redirect_uri,
            },
        )
        response.raise_for_status()
        return GmailTokenResponse.model_validate(response.json())

    def refresh(self, refresh_token: str) -> GmailTokenResponse:
        response = self._client.post(
            TOKEN_URL,
            data={
                "client_id": settings.gmail_oauth_client_id,
                "client_secret": settings.gmail_oauth_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
        response.raise_for_status()
        return GmailTokenResponse.model_validate(response.json())

    @staticmethod
    def _headers(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def profile(self, access_token: str) -> GmailProfile:
        response = self._client.get(
            f"{API_URL}/users/me/profile", headers=self._headers(access_token)
        )
        response.raise_for_status()
        return GmailProfile.model_validate(response.json())

    def labels(self, access_token: str) -> list[GmailLabel]:
        response = self._client.get(
            f"{API_URL}/users/me/labels", headers=self._headers(access_token)
        )
        response.raise_for_status()
        return GmailLabelList.model_validate(response.json()).labels

    def create_label(self, access_token: str, name: str) -> GmailLabel:
        response = self._client.post(
            f"{API_URL}/users/me/labels",
            headers=self._headers(access_token),
            json={
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        )
        response.raise_for_status()
        return GmailLabel.model_validate(response.json())

    def watch(
        self,
        access_token: str,
        mode: EmailMonitoringMode,
        scan_label_id: str,
    ) -> GmailWatchResponse:
        label_id = "INBOX" if mode is EmailMonitoringMode.ALL else scan_label_id
        response = self._client.post(
            f"{API_URL}/users/me/watch",
            headers=self._headers(access_token),
            json={
                "topicName": settings.gmail_pubsub_topic,
                "labelIds": [label_id],
                "labelFilterBehavior": "INCLUDE",
            },
        )
        response.raise_for_status()
        return GmailWatchResponse.model_validate(response.json())

    def stop(self, access_token: str) -> None:
        response = self._client.post(
            f"{API_URL}/users/me/stop", headers=self._headers(access_token)
        )
        response.raise_for_status()

    def history(
        self,
        access_token: str,
        start_history_id: str,
        label_id: str,
        page_token: str | None = None,
    ) -> GmailHistoryResponse:
        params: list[tuple[str, str | int | float | None]] = [
            ("startHistoryId", start_history_id),
            ("historyTypes", "messageAdded"),
            ("labelId", label_id),
        ]
        if page_token:
            params.append(("pageToken", page_token))
        response = self._client.get(
            f"{API_URL}/users/me/history",
            headers=self._headers(access_token),
            params=params,
        )
        response.raise_for_status()
        return GmailHistoryResponse.model_validate(response.json())

    def message(self, access_token: str, message_id: str) -> GmailMessage:
        response = self._client.get(
            f"{API_URL}/users/me/messages/{message_id}",
            headers=self._headers(access_token),
            params={"format": "full"},
        )
        response.raise_for_status()
        return GmailMessage.model_validate(response.json())

    def messages_after(
        self,
        access_token: str,
        after_epoch: int,
        label_id: str,
        page_token: str | None = None,
    ) -> GmailMessageList:
        params: dict[str, str | int] = {
            "q": f"after:{after_epoch}",
            "labelIds": label_id,
            "maxResults": 100,
        }
        if page_token:
            params["pageToken"] = page_token
        response = self._client.get(
            f"{API_URL}/users/me/messages",
            headers=self._headers(access_token),
            params=params,
        )
        response.raise_for_status()
        return GmailMessageList.model_validate(response.json())

    def recent_messages(
        self,
        access_token: str,
        label_id: str | None,
        limit: int,
        page_token: str | None = None,
    ) -> GmailMessageList:
        params: dict[str, str | int] = {"maxResults": limit}
        if label_id:
            params["labelIds"] = label_id
        if page_token:
            params["pageToken"] = page_token
        response = self._client.get(
            f"{API_URL}/users/me/messages",
            headers=self._headers(access_token),
            params=params,
        )
        response.raise_for_status()
        return GmailMessageList.model_validate(response.json())

    def attachment(
        self, access_token: str, message_id: str, attachment_id: str
    ) -> GmailAttachmentData:
        response = self._client.get(
            f"{API_URL}/users/me/messages/{message_id}/attachments/{attachment_id}",
            headers=self._headers(access_token),
        )
        response.raise_for_status()
        return GmailAttachmentData.model_validate(response.json())

    def modify_labels(
        self,
        access_token: str,
        message_id: str,
        *,
        add: list[str],
        remove: list[str],
    ) -> None:
        response = self._client.post(
            f"{API_URL}/users/me/messages/{message_id}/modify",
            headers=self._headers(access_token),
            json={"addLabelIds": add, "removeLabelIds": remove},
        )
        response.raise_for_status()

    def revoke(self, token: str) -> None:
        response = self._client.post(REVOKE_URL, params={"token": token})
        response.raise_for_status()

    def close(self) -> None:
        self._client.close()
