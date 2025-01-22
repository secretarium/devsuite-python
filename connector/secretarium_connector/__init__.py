import os
import asyncio
import json
import logging
import base64
from . import utils as Utils, key
from asn1crypto.core import Sequence
from typing import Self, Callable, Dict, List, Any, Optional, Union
from logging import Logger
from dataclasses import dataclass
from websockets import ConnectionClosed, connect, protocol as websocket_protocol
from websockets.typing import Subprotocol
from websockets.asyncio.client import ClientConnection
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Key = key.Key

logger = logging.getLogger("secretarium.connector")
logger.addHandler(logging.NullHandler())

@dataclass
class SCPEndpoint:
    url: str
    knownTrustedKey: str

@dataclass
class SCPOptions:
    logger: Optional[Logger] = logger
    gatewayTimeout: Optional[int] = 1
    connectTimeout: Optional[int] = 5

@dataclass
class SCPSession:
    cryptoKey: AESGCM
    iv: bytes

@dataclass
class SCPProto:
    protoID: str
    protoVersion: str
    serverType: str
    serverVersion: str
    serverTag: str

@dataclass
class TransactionNotificationHandlers:
    onError: List[Callable[[str, str], None]]
    onResult: List[Callable[[Any, str], None]]
    onAcknowledged: List[Callable[[str], None]]
    onCommitted: List[Callable[[str], None]]
    onExecuted: List[Callable[[str], None]]
    promise: asyncio.Future[Any]
    failed: bool = False

class SCP:
    def __init__(self, options: SCPOptions = SCPOptions()):
        self._socket: Optional[ClientConnection] = None
        self._options: SCPOptions = options
        self._endpoint: Optional[SCPEndpoint] = None
        self._connectionState: websocket_protocol.State = websocket_protocol.State.CLOSED
        self._onStateChange: Optional[Callable[[websocket_protocol.State], None]] = None
        self._onError: Optional[Callable[[str], None]] = None
        self._session: Optional[SCPSession] = None
        self._readyFuture = asyncio.Future[Self]()
        self.requests: Dict[str, Optional[TransactionNotificationHandlers]] = {}

    def onError(self, callback: Callable[[str], None]):
        self._onError = callback

    def onStateChange(self, callback: Callable[[websocket_protocol.State], None]):
        self._onStateChange = callback

    def _updateState(self, state: websocket_protocol.State):
        self._connectionState = state
        if self._onStateChange is not None:
            self._onStateChange(state)

    def isConnected(self):
        return self._connectionState == websocket_protocol.State.OPEN

    def getEndpoint(self):
        return self._endpoint

    def reset(self, options: Optional[SCPOptions] = None):
        if self._connectionState != websocket_protocol.State.CLOSED:
            asyncio.create_task(self.close())
        self._options = self._options if options is None else options
        self._session = None
        self._onStateChange = None
        self._onError = None
        self._readyFuture = asyncio.Future[Self]()
        self.requests = {}
        self._updateState(websocket_protocol.State.CLOSED)
        return self

    async def _encrypt(self, data: bytes) -> bytes:
        if (self._session is None):
            raise Exception("Session is not set")
        ivOffset = os.urandom(16)
        iv = Utils.increment_by(self._session.iv, ivOffset)[0:12]
        aesgcm: AESGCM = self._session.cryptoKey
        encrypted = aesgcm.encrypt(iv, data, None)
        return ivOffset + encrypted

    async def _decrypt(self, data: bytes) -> bytes:
        if (self._session is None):
            raise Exception("Session is not set")
        iv = Utils.increment_by(self._session.iv, data[0:16])[0:12]
        aesgcm: AESGCM = self._session.cryptoKey
        return aesgcm.decrypt(iv, data[16:], None)

    async def _performClusterNegotiation(self, userKey: Key):

        if self._socket is None:
            raise Exception("Socket is not set")
        if self._endpoint is None:
            raise Exception("Endpoint is not set")

        ecdh = ec.generate_private_key(ec.SECP256R1())
        ecdhPubKeyRaw = ecdh.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]

        await self._socket.send(bytes([0, 0, 0, 1]) + ecdhPubKeyRaw, False)

        serverHello = await asyncio.wait_for(self._socket.recv(decode=False), timeout=self._options.connectTimeout)
        if isinstance(serverHello, str):
            serverHello = serverHello.encode('utf-8')
        serverHello = serverHello[4:]

        pow = self._computeProofOfWork(bytes(serverHello[0:32]))

        trustedKey = base64.b64decode(self._endpoint.knownTrustedKey)
        clientProofOfWork = pow + trustedKey

        await self._socket.send(bytes([0, 0, 0, 1]) + clientProofOfWork, False)
        serverIdentity = await asyncio.wait_for(self._socket.recv(decode=False), timeout=self._options.connectTimeout)
        if isinstance(serverIdentity, str):
            serverIdentity = serverIdentity.encode('utf-8')
        serverIdentity = serverIdentity[4:]

        preMasterSecret = bytes(serverIdentity[0:32])

        serverEcdhPubKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes([4]) + serverIdentity[32:96])
        serverEcdsaPubKey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes([4]) + serverIdentity[-64:])

        commonSecret = ecdh.exchange(ec.ECDH(), serverEcdhPubKey)
        hash = hashes.Hash(hashes.SHA256())
        hash.update(commonSecret)
        sha256Common = hash.finalize()

        symmetricKey = bytes(a ^ b for (a, b) in zip(preMasterSecret, sha256Common))
        iv = symmetricKey[16:]
        key = symmetricKey[0:16]
        cryptoKey = AESGCM(key)
        self._session = SCPSession(cryptoKey, iv)

        cryptoKeyPair = userKey.getCryptoKeyPair()
        publicKeyRaw = await userKey.getRawPublicKey()

        nonce = os.urandom(32)
        # This produces a DER encoded signature which must be converted to a raw signature
        signedNonceDER = cryptoKeyPair.sign(nonce, ec.ECDSA(hashes.SHA256()))

        sequence: Any = Sequence.load(encoded_data=signedNonceDER, strict=False) # type: ignore
        r, s = sequence[0].native, sequence[1].native

        r_bytes: bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        s_bytes: bytes = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        curve_size = cryptoKeyPair.curve.key_size // 8
        r_bytes = r_bytes.rjust(curve_size, b'\x00')
        s_bytes = s_bytes.rjust(curve_size, b'\x00')
        signedNonce = r_bytes + s_bytes

        clientProofOfIdentity = nonce + ecdhPubKeyRaw + publicKeyRaw + signedNonce
        encryptedClientProofOfIdentity = await self._encrypt(clientProofOfIdentity)

        await self._socket.send(bytes([0, 0, 0, 1]) + encryptedClientProofOfIdentity, False)
        serverProofOfIdentityEncrypted = await asyncio.wait_for(self._socket.recv(decode=False), timeout=30)
        if isinstance(serverProofOfIdentityEncrypted, str):
            serverProofOfIdentityEncrypted = serverProofOfIdentityEncrypted.encode('utf-8')
        serverProofOfIdentityEncrypted = serverProofOfIdentityEncrypted[4:]

        serverProofOfIdentity = await self._decrypt(bytes(serverProofOfIdentityEncrypted))

        welcome = bytes(b'Hey you! Welcome to Secretarium!')
        toVerify = serverProofOfIdentity[0:32] + welcome

        # This is a raw signature which must be converted to a DER encoded signature for the verify method
        serverSignedHashRaw = serverProofOfIdentity[32:96]

        rr = int.from_bytes(serverSignedHashRaw[0:32], 'big')
        rs = int.from_bytes(serverSignedHashRaw[32:], 'big')

        serverSignedHashDER = encode_dss_signature(rr, rs)
        serverEcdsaPubKey.verify(serverSignedHashDER, toVerify, ec.ECDSA(hashes.SHA256()))

        self._updateState(websocket_protocol.State.OPEN)
        asyncio.create_task(self._onMessage())

    async def _connect(self, url: str, userKey: Key, knownTrustedKey: Optional[str] | Optional[bytes]):

        knownTrustedKeyStr: str = ""
        if knownTrustedKey is None:
            knownTrustedKeyStr = base64.b64encode(os.urandom(64)).decode('utf-8')
        if isinstance(knownTrustedKey, str):
            knownTrustedKeyStr = knownTrustedKey
        if isinstance(knownTrustedKey, bytes):
            knownTrustedKeyStr = knownTrustedKey.decode('utf-8')

        self._endpoint = SCPEndpoint(url=url, knownTrustedKey=knownTrustedKeyStr)
        self._updateState(websocket_protocol.State.CONNECTING)
        self._socket = await connect(
            uri=self._endpoint.url,
            subprotocols=[Subprotocol("pair1.sp.nanomsg.org")],
            open_timeout=5,
            close_timeout=5
        )

        try:
            protocol: Optional[SCPProto] = None
            try:
                protoInfo = await asyncio.wait_for(self._socket.recv(decode=False), timeout=self._options.gatewayTimeout)
                protoInfo = protoInfo[4:]
                if isinstance(protoInfo, bytes):
                    protoInfo = str(protoInfo, 'utf-8')
                if not isinstance(protoInfo, str):
                    raise Exception("Invalid protocol information")
                main, serverTag = protoInfo.split(" ", 1)
                protoID, protoVersion, serverID = main.split("-")
                serverType, serverVersion = serverID.split("_", 1)
                protocol = SCPProto(protoID, protoVersion, serverType, serverVersion, serverTag)

            except Exception as e:
                if not isinstance(e, asyncio.TimeoutError):
                    raise e

            if protocol is None:
                await self._performClusterNegotiation(userKey)
            else:
                if self._options.logger is not None: self._options.logger.debug(f"Secretarium protocol: {protocol}")
                raise SCPNotImplemented(f"Protocol {protocol.protoID} v{protocol.protoVersion} is not supported")

        except Exception as e:
            if isinstance(e, SCPNotImplemented):
                if self._readyFuture._state == "PENDING":
                    self._readyFuture.set_exception(e)
                return
            if isinstance(e, SCPTimeout):
                if self._readyFuture._state == "PENDING":
                    self._readyFuture.set_exception(e)
                return
            self._updateState(websocket_protocol.State.CLOSED)
            if self._onError is not None:
                if isinstance(e, ConnectionClosed) and e.rcvd is not None:
                    self._onError(f"Connect: Connection closed with code {e.rcvd.code}, reason: {e.rcvd.reason}")
                else:
                    self._onError(f"Connect: Connection closed: {e}")
            if self._readyFuture._state == "PENDING":
                    self._readyFuture.set_result(self)

    def connect(self, uri: str, userKey: Key, knownTrustedKey: Optional[str] | Optional[bytes] = None):
        asyncio.create_task(self._connect(uri, userKey, knownTrustedKey))
        return self._readyFuture

    async def _onMessage(self):
        if self._socket is None:
            return
        try:
            while self._connectionState == websocket_protocol.State.OPEN:
                if self._readyFuture._state == "PENDING":
                    self._readyFuture.set_result(self)
                message = await self._socket.recv(decode=False)
                if isinstance(message, str):
                    message = message.encode('utf-8')
                message = message[4:]
                json = await self._decrypt(message)
                await self._notify(json)

        except asyncio.TimeoutError:
            asyncio.create_task(self._onMessage())
        except Exception as e:
            if self._onError is not None:
                self._onError(f"Error while listening: {e}")

    async def _notify(self, data: bytes):
        try:
            o = json.JSONDecoder().decode(str(data.decode('utf-8')))
            if self._options.logger is not None: self._options.logger.debug(f"Secretarium received: {o}")
            requestId = o["requestId"]
            if requestId in self.requests:
                x = self.requests[requestId]
                if x is None:
                    if self._onError is not None:
                        self._onError(f"Request {requestId} not found")
                    return
                if "error" in o:
                    x.failed = True
                    for cb in x.onError:
                        cb(o["error"], o["requestId"])
                    if not x.promise.done():
                        x.promise.set_exception(o["error"])
                elif "result" in o:
                    for cb in x.onResult:
                        cb(o["result"], o["requestId"])
                    if not x.promise.done():
                        x.promise.set_result(o["result"])
                elif "state" in o:
                    match o["state"].lower():
                        case "acknowledged":
                            for cb in x.onAcknowledged:
                                cb(o["requestId"], None)
                        case "committed":
                            for cb in x.onCommitted:
                                cb(o["requestId"], None)
                        case "executed":
                            for cb in x.onExecuted:
                                cb(o["requestId"], None)
                        case "failed":
                            x.failed = True
                            for cb in x.onError:
                                cb("Transaction Failed", o["requestId"])
                            if not x.promise.done():
                                x.promise.set_exception(o["error"])

        except Exception as e:
            if self._onError is not None:
                self._onError(f"Error while notifying: {e.__class__.__name__}: {e}")

    def _computeProofOfWork(self, nonce: bytes) -> bytes:
        return nonce # proof-of-work verification is currently deactivated

    def newTx(self, app: str, command: str, requestId: Optional[str] = None, args: Optional[Union[Dict[str, Any], str]] = None):
        rid = requestId or 'rid-' + app + '-' + command + '-' + os.urandom(8).hex()
        return Tx(self, app, command, rid, args)

    async def _prepare(self, query: Any):

        if self._options.logger is not None: self._options.logger.debug(f"Secretarium sending: {query}")
        queryString = bytes(json.JSONEncoder().encode(query), 'utf-8')
        encrypted = await self._encrypt(queryString)

        return encrypted

    async def send(self, app: str, command: str, requestId: str, args: Optional[Union[Dict[str, Any], str]]):
        try:

            encrypted = await self._prepare({
                "dcapp": app,
                "function": command,
                "requestId": requestId,
                "args": args
            })

            if self._socket is not None:
                await self._socket.send(bytes([0, 0, 0, 1]) + encrypted, False)

        except Exception as e:
            if self._onError is not None:
                self._onError(f"Error while sending: {e}")
            x = self.requests[requestId]
            if x is not None:
                x.failed = True
                x.promise.set_exception(e)

    async def close(self):
        if self._socket is not None:
            await self._socket.close()


class Tx:
    def __init__(self, scp: SCP, app: str, command: str, requestId: str, args: Optional[Union[Dict[str, Any], str]]):
        self.scp = scp
        self.app = app
        self.command = command
        self.requestId = requestId
        self.args = args
        self.promise = asyncio.Future[Any]()
        self.cbs = TransactionNotificationHandlers([], [], [], [], [], self.promise)
        self.cbs.onResult.append(lambda message, r: self.promise.set_result(message))

    def _wrapper(self, callback: Callable[[Any, str], None] | Callable[[Any], None]| Callable[[], None]) -> Callable[..., Any]:
        def _innerWrapper(d: Any | None, r: str | None) -> None:
            if callable(callback):
                if len(callback.__code__.co_varnames) == 0:
                    return callback() # type: ignore
                elif len(callback.__code__.co_varnames) == 1:
                    return callback(d) # type: ignore
                else :
                    return callback(d, r) # type: ignore
        return _innerWrapper

    def onError(self, callback: Callable[[Any, str], None] | Callable[[Any], None]):
        self.cbs.onError.append(self._wrapper(callback))
        return self

    def onResult(self, callback: Callable[[Any, str], None] | Callable[[Any], None]):
        self.cbs.onResult.append(self._wrapper(callback))
        return self

    def onAcknowledged(self, callback: Callable[[str], None] | Callable[[], None]):
        self.cbs.onAcknowledged.append(self._wrapper(callback))
        return self

    def onCommitted(self, callback: Callable[[str], None] | Callable[[], None]):
        self.cbs.onCommitted.append(self._wrapper(callback))
        return self

    def onExecuted(self, callback: Callable[[str], None] | Callable[[], None]):
        self.cbs.onExecuted.append(self._wrapper(callback))
        return self

    def send(self):
        self.scp.requests[self.requestId] = self.cbs
        asyncio.create_task(self.scp.send(self.app, self.command, self.requestId, self.args))
        return self.promise

class SCPError(Exception):
    pass

class SCPNotImplemented(SCPError):
    pass

class SCPTimeout(SCPError):
    pass