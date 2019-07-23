import json
import logging
import asyncio

import indy

from core import AsyncReqResp


class WalletConnectionException(Exception):
    pass


class WalletConnection:

    def __init__(self, agent_name: str, pass_phrase: str, ephemeral=False):
        self.__agent_name = agent_name
        self.__pass_phrase = pass_phrase
        self.__ephemeral = ephemeral
        self.__initialized = False
        self.__wallet_handle = None
        self.__wallet_config = None
        self.__wallet_credentials = None

    async def connect(self):
        """ Create if not already exists and open wallet. """
        if self.__initialized:
            return
        wallet_suffix = "wallet"
        if self.__ephemeral:
            wallet_suffix = "ephemeral_wallet"
        wallet_name = '{}-{}'.format(self.__agent_name, wallet_suffix)

        wallet_config = json.dumps({"id": wallet_name})
        wallet_credentials = json.dumps({"key": self.__pass_phrase})
        self.__wallet_config = wallet_config
        self.__wallet_credentials = wallet_credentials

        # Handle ephemeral wallets
        if self.__ephemeral:
            try:
                await indy.wallet.delete_wallet(wallet_config, wallet_credentials)
                logging.debug("Removing ephemeral wallet.")
            except indy.error.IndyError as e:
                if e.error_code is indy.error.ErrorCode.WalletNotFoundError:
                    pass  # This is ok, and expected.
                elif e.error_code is indy.error.ErrorCode.CommonInvalidState:
                    pass
                else:
                    logging.error("Unexpected Indy Error: {}".format(e))
        try:
            await indy.wallet.create_wallet(wallet_config, wallet_credentials)
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
                wallet_config,
                wallet_credentials
            )
            self.__initialized = True
        except Exception as e:
            logging.error(str(e))
            logging.error("Could not open wallet!")
            raise WalletConnectionException()

    async def disconnect(self):
        """ Close the wallet and set back state to non initialised. """
        if self.__wallet_handle:
            await indy.wallet.close_wallet(self.__wallet_handle)
        self.__initialized = False
        self.__wallet_handle = None

    async def delete(self):
        if self.__wallet_handle:
            await indy.wallet.delete_wallet(self.__wallet_config, self.__wallet_credentials)
            return True
        else:
            raise WalletConnectionException()

    async def create_and_store_my_did(self):
        if self.__wallet_handle:
            did, verkey = await indy.did.create_and_store_my_did(self.__wallet_handle, "{}")
            return did, verkey
        else:
            raise WalletConnectionException()

    async def create_key(self):
        if self.__wallet_handle:
            verkey = await indy.did.create_key(self.__wallet_handle, "{}")
            return verkey
        else:
            raise WalletConnectionException()

    @property
    def ephemeral(self):
        return self.__ephemeral

    @property
    def initialized(self):
        return self.__initialized


class WalletMultiConnection:

    COMMAND_CONNECT = 'connect'
    COMMAND_CLOSE = 'close'
    COMMAND_INITIALIZED = 'initialized'
    COMMAND_CREATE_AND_STORE_MY_DID = 'create_and_store_my_did'
    COMMAND_CREATE_KEY = 'create_key'
    COMMAND_ALIVE = 'alive'
    COMMAND_DELETE = 'delete'

    def __init__(self, agent_name: str, pass_phrase: str, ephemeral=False, timeout=1):
        self.__listener = None
        self.__agent_name = agent_name
        self.__pass_phrase = pass_phrase
        self.__ephemeral = ephemeral
        self.__timeout = timeout

    @classmethod
    async def connect(cls, agent_name: str, pass_phrase: str, ephemeral=False, timeout=1):
        wallet_suffix = "wallet"
        if ephemeral:
            wallet_suffix = "ephemeral_wallet"
        wallet_name = '{}-{}'.format(agent_name, wallet_suffix)
        req = AsyncReqResp(address='async-wallet:{}'.format(wallet_name))
        instance = WalletMultiConnection(agent_name, pass_phrase, ephemeral, timeout)
        instance.__listener = req
        success, resp = await req.req(dict(command=cls.COMMAND_ALIVE), timeout=timeout)
        if not success:
            asyncio.ensure_future(instance.__async_runner())
            success, resp = await req.req(dict(command=cls.COMMAND_ALIVE), timeout=10)
            if not success:
                raise WalletConnectionException()
        return instance

    async def disconnect(self):
        await self.__listener.req(dict(command=self.COMMAND_CLOSE), timeout=1.0)

    async def delete(self):
        success, resp = await self.__listener.req(
            dict(command=self.COMMAND_DELETE),
            timeout=self.__timeout
        )
        if success:
            return resp
        else:
            raise WalletConnectionException()

    async def create_and_store_my_did(self):
        success, resp = await self.__listener.req(
            dict(command=self.COMMAND_CREATE_AND_STORE_MY_DID),
            timeout=self.__timeout
        )
        if success:
            return resp
        else:
            raise WalletConnectionException()

    async def create_key(self):
        success, resp = await self.__listener.req(
            dict(command=self.COMMAND_CREATE_KEY), timeout=self.__timeout
        )
        if success:
            return resp
        else:
            raise WalletConnectionException()

    async def get_initialized(self):
        success, resp = await self.__listener.req(
            dict(command=self.COMMAND_INITIALIZED), timeout=self.__timeout
        )
        if success:
            return resp
        else:
            raise WalletConnectionException()

    async def __async_runner(self):
        await self.__listener.start_listening()
        try:
            wallet = WalletConnection(self.__agent_name, self.__pass_phrase, self.__ephemeral)
            await wallet.connect()
            try:
                # wait initialization
                while True:
                    req, chan = await self.__listener.wait_req()
                    command = req['command']
                    args = req.get('args', ())
                    kwargs = req.get('kwargs', {})
                    if command == self.COMMAND_CLOSE:
                        break
                    elif command == self.COMMAND_ALIVE:
                        await chan.write(req)
                    elif command == self.COMMAND_INITIALIZED:
                        value = wallet.initialized
                        await chan.write(value)
                    elif command == self.COMMAND_CREATE_AND_STORE_MY_DID:
                        values = await wallet.create_and_store_my_did()
                        await chan.write(values)
                    elif command == self.COMMAND_CREATE_KEY:
                        values = await wallet.create_key()
                        await chan.write(values)
                    elif command == self.COMMAND_DELETE:
                        values = await wallet.delete()
                        await chan.write(values)
            finally:
                await wallet.disconnect()
        finally:
            await self.__listener.stop_listening()
