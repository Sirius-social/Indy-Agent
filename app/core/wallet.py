import json
import uuid
import logging
import asyncio

import indy
from django.conf import settings

from core import AsyncReqResp


class BaseWalletException(Exception):
    error_code = None
    error_message = None

    def __init__(self, error_message=None):
        self.error_message = error_message


WALLET_EXCEPTION_CODES = {}


class WalletExceptionMeta(type):

    def __new__(mcs, name, bases, class_dict):
        cls = type.__new__(mcs, name, bases, class_dict)
        WALLET_EXCEPTION_CODES[cls.error_code] = cls
        return cls


class WalletAlreadyExists(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 1


class WalletNotCreated(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 2


class WalletAccessDenied(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 3


class WalletConnectionException(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 4


class WalletIsNotOpen(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 5


class AgentTimeOutError(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 6


def raise_wallet_exception(error_code, error_message):
    exception_cls = WALLET_EXCEPTION_CODES.get(error_code, None)
    if exception_cls:
        raise exception_cls(error_message)
    else:
        raise RuntimeError(error_message)


class WalletConnection:

    def __init__(self, agent_name: str, pass_phrase: str, ephemeral=False):
        self.__agent_name = agent_name
        self.__pass_phrase = pass_phrase
        self.__ephemeral = ephemeral
        self.__is_open = False
        self.__wallet_handle = None
        wallet_address = self.make_wallet_address(agent_name)
        cfg = {"id": wallet_address}
        cfg.update(settings.INDY.get('WALLET_SETTINGS', {}).get('config', {}))
        cred = {"key": self.__pass_phrase}
        cred.update(settings.INDY.get('WALLET_SETTINGS', {}).get('credentials', {}))
        self.__wallet_config = json.dumps(cfg)
        self.__wallet_credentials = json.dumps(cred)

    def check_credentials(self, agent_name: str, pass_phrase: str):
        if not self.__wallet_handle:
            raise WalletIsNotOpen(error_message='Open wallet at first')
        else:
            return self.__agent_name == agent_name and self.__pass_phrase == pass_phrase

    @staticmethod
    def make_wallet_address(agent_name):
        value = '{}_{}'.format(agent_name, 'wallet')
        for ch in ['-', '*', '?', '=']:
            value = value.replace(ch, '_')
        return value

    async def create(self):
        try:
            await indy.wallet.create_wallet(self.__wallet_config, self.__wallet_credentials)
        except indy.error.IndyError as e:
            if e.error_code is indy.error.ErrorCode.WalletAlreadyExistsError:
                raise WalletAlreadyExists(error_message=e.message)
            else:
                raise e

    async def open(self):
        """Open already created wallet"""
        if self.__wallet_handle:
            await indy.wallet.close_wallet(self.__wallet_handle)
        try:
            self.__wallet_handle = await indy.wallet.open_wallet(
                self.__wallet_config,
                self.__wallet_credentials
            )
            self.__is_open = True
        except indy.error.IndyError as e:
            if e.error_code is indy.error.ErrorCode.WalletNotFoundError:
                raise WalletNotCreated(error_message=e.message)
            elif e.error_code is indy.error.ErrorCode.WalletAccessFailed:
                raise WalletAccessDenied(error_message=e.message)
            else:
                raise e

    async def close(self):
        """ Close the wallet and set back state to non initialised. """
        if self.__wallet_handle:
            await indy.wallet.close_wallet(self.__wallet_handle)
        self.__is_open = False
        self.__wallet_handle = None

    async def delete(self):
        if self.__wallet_handle:
            await self.close()
        await indy.wallet.delete_wallet(self.__wallet_config, self.__wallet_credentials)

    async def connect(self):
        """ Create if not already exists and open wallet. """
        if self.__is_open:
            return
        # Handle ephemeral wallets
        if self.__ephemeral:
            try:
                await indy.wallet.delete_wallet(self.__wallet_config, self.__wallet_credentials)
                logging.debug("Removing ephemeral wallet.")
            except indy.error.IndyError as e:
                if e.error_code is indy.error.ErrorCode.WalletNotFoundError:
                    pass  # This is ok, and expected.
                elif e.error_code is indy.error.ErrorCode.CommonInvalidState:
                    pass
                else:
                    logging.error("Unexpected Indy Error: {}".format(e))
        try:
            await indy.wallet.create_wallet(self.__wallet_config, self.__wallet_credentials)
        except indy.error.IndyError as e:
            if e.error_code is indy.error.ErrorCode.WalletAlreadyExistsError:
                pass  # This is ok, and expected.
            else:
                logging.error("Unexpected Indy Error: {}".format(e))
        except Exception as e:
            print(e)

        try:
            if self.__wallet_handle:
                await indy.wallet.close_wallet(self.__wallet_handle)
            self.__wallet_handle = await indy.wallet.open_wallet(
                self.__wallet_config,
                self.__wallet_credentials
            )
            self.__is_open = True
        except Exception as e:
            logging.error(str(e))
            logging.error("Could not open wallet!")
            raise WalletConnectionException(error_message=str(e))

    async def create_and_store_my_did(self):
        if self.__wallet_handle:
            did, verkey = await indy.did.create_and_store_my_did(self.__wallet_handle, "{}")
            return did, verkey
        else:
            raise WalletIsNotOpen()

    async def create_key(self):
        if self.__wallet_handle:
            verkey = await indy.did.create_key(self.__wallet_handle, "{}")
            return verkey
        else:
            raise WalletIsNotOpen()

    @property
    def is_open(self):
        return self.__is_open


class WalletAgent:

    COMMAND_PING = 'ping'
    COMMAND_PONG = 'pong'
    COMMAND_OPEN = 'open'
    COMMAND_CLOSE = 'close'
    COMMAND_IS_OPEN = 'is_open'
    COMMAND_CREATE_KEY = 'create_key'
    COMMAND_CREATE_AND_STORE_MY_DID = 'create_and_store_my_did'
    TIMEOUT = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_REQUEST']
    TIMEOUT_START = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_START']

    @classmethod
    async def ping(cls, agent_name: str, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        ping = dict(
            command=cls.COMMAND_PING,
            marker=uuid.uuid4().hex
        )
        success, pong = await requests.req(ping, timeout=timeout)
        if success:
            return pong['command'] == cls.COMMAND_PONG and pong['marker'] == ping['marker']
        else:
            return False

    @classmethod
    async def is_open(cls, agent_name: str, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_IS_OPEN,
        )
        success, resp = await requests.req(packet, timeout=timeout)
        if success:
            error = resp.get('error', None)
            if error:
                raise_wallet_exception(**error)
            else:
                return resp['ret']
        else:
            return False

    @classmethod
    async def open(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_OPEN,
            pass_phrase=pass_phrase,
        )
        success, resp = await requests.req(packet, timeout=timeout)
        if success:
            error = resp.get('error', None)
            if error:
                raise_wallet_exception(**error)
        else:
            raise AgentTimeOutError()

    @classmethod
    async def close(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_CLOSE,
            pass_phrase=pass_phrase,
        )
        success, resp = await requests.req(packet, timeout=timeout)
        if success:
            error = resp.get('error', None)
            if error:
                raise_wallet_exception(**error)
        else:
            raise AgentTimeOutError()

    @classmethod
    async def create_and_store_my_did(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_CREATE_AND_STORE_MY_DID,
            pass_phrase=pass_phrase,
        )
        success, resp = await requests.req(packet, timeout=timeout)
        if success:
            error = resp.get('error', None)
            if error:
                raise_wallet_exception(**error)
            else:
                return resp['ret']
        else:
            raise AgentTimeOutError()

    @classmethod
    async def create_key(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_CREATE_KEY,
            pass_phrase=pass_phrase,
        )
        success, resp = await requests.req(packet, timeout=timeout)
        if success:
            error = resp.get('error', None)
            if error:
                raise_wallet_exception(**error)
            else:
                return resp['ret']
        else:
            raise AgentTimeOutError()

    @classmethod
    async def process(cls, agent_name: str):
        address = WalletConnection.make_wallet_address(agent_name)
        logging.debug('Wallet Agent "%s" is started' % agent_name)
        listener = AsyncReqResp(address)
        await listener.start_listening()
        wallet__ = None

        def check_access_denied(pass_phrase_):
            if not wallet__.check_credentials(agent_name, pass_phrase_):
                raise WalletAccessDenied()

        try:
            try:
                while True:
                    req, chan = await listener.wait_req()
                    logging.debug('Received request: "%s"' % repr(req))
                    command = req['command']
                    pass_phrase = req.get('pass_phrase', None)
                    try:
                        if command == cls.COMMAND_PING:
                            req['command'] = cls.COMMAND_PONG
                            await chan.write(req)
                        elif command == cls.COMMAND_OPEN:
                            if wallet__ is None:
                                w = WalletConnection(agent_name, pass_phrase)
                                await w.open()
                                wallet__ = w
                            else:
                                check_access_denied(pass_phrase)
                                if not wallet__.is_open:
                                    await wallet__.open()
                            await chan.write(req)
                        elif command == cls.COMMAND_CLOSE:
                            if wallet__:
                                check_access_denied(pass_phrase)
                                if wallet__.is_open:
                                    await wallet__.close()
                            await chan.write(req)
                            break
                        elif command == cls.COMMAND_CREATE_KEY:
                            if wallet__ is None:
                                raise WalletIsNotOpen()
                            else:
                                check_access_denied(pass_phrase)
                                ret = await wallet__.create_key()
                                await chan.write(dict(ret=ret))
                        elif command == cls.COMMAND_CREATE_AND_STORE_MY_DID:
                            if wallet__ is None:
                                raise WalletIsNotOpen()
                            else:
                                check_access_denied(pass_phrase)
                                ret = await wallet__.create_and_store_my_did()
                                await chan.write(dict(ret=ret))
                        elif command == cls.COMMAND_IS_OPEN:
                            ret = wallet__ is not None and wallet__.is_open
                            await chan.write(dict(ret=ret))
                    except BaseWalletException as e:
                        req['error'] = dict(error_code=e.error_code, error_message=e.error_message)
                        await chan.write(req)
                    else:
                        logging.exception('Agent routine ERROR')
            finally:
                if wallet__ and wallet__.is_open:
                    await wallet__.close()
        finally:
            await listener.stop_listening()
            logging.debug('Wallet Agent "%s" is stopped' % agent_name)
