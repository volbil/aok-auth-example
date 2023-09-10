from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from pydantic import BaseModel
from fastapi import FastAPI
import aiohttp
import secrets
import hashlib
import hmac

HMAC_KEY = "secret"


class AuthArgs(BaseModel):
    signature: str
    message: str
    address: str


def generate_hmac(payload, key):
    return hmac.new(
        bytes(key, "UTF-8"), bytes(payload, "UTF-8"), hashlib.sha256
    ).hexdigest()


def check_hmac(payload, key, hmac_signature):
    return generate_hmac(payload, key) == hmac_signature


async def check_signature(args: AuthArgs):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://api.aok.network/verify",
            json={
                "signature": args.signature,
                "message": args.message,
                "address": args.address,
            },
        ) as r:
            return await r.json()


def create_app() -> FastAPI:
    app = FastAPI()

    app.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/auth")
    async def auth(args: AuthArgs):
        # Split message
        message_split = args.message.split("|")

        # Make sure we have 3 parts
        if len(message_split) != 3:
            return {"error": "Failed (bad message)"}

        secret, timestamp, hmac_signature = message_split

        # Check if message still valid
        expiration = datetime.fromtimestamp(int(timestamp))
        if datetime.utcnow() > expiration:
            return {"error": "Failed (expired)"}

        # Check hmac to make sure message is valid
        if not check_hmac(f"{secret}|{timestamp}", HMAC_KEY, hmac_signature):
            return {"error": "Failed (hmac)"}

        # Check wallet signature
        check = await check_signature(args)
        if not check["result"]:
            return {"error": "Failed (wallet signature)"}

        return {"token": secrets.token_urlsafe(16)}

    @app.get("/message")
    def message():
        # Generate random text
        text = secrets.token_urlsafe(12)

        # Message will expire in 1 minute
        expiration = int((datetime.utcnow() + timedelta(minutes=1)).timestamp())

        # Join text and timestamp
        payload = f"{text}|{expiration}"

        # Generate hmac signature
        hmac_signature = generate_hmac(payload, HMAC_KEY)

        return {
            "message": f"{payload}|{hmac_signature}",
        }

    return app
