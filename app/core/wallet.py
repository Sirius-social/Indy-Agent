import json
import logging

import indy


class WalletConnectionException(Exception):
    pass


class WalletConnection:

    def __init__(self, agent_name: str, pass_phrase: str, ephemeral=False):
        self.__agent_name = agent_name
        self.__pass_phrase = pass_phrase
        self.__ephemeral = ephemeral
        self.__initialized = False
        self.__wallet_handle = None

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

        # Handle ephemeral wallets
        if self.__ephemeral:
            try:
                await indy.wallet.delete_wallet(wallet_config, wallet_credentials)
                logging.debug("Removing ephemeral wallet.")
            except indy.error.IndyError as e:
                if e.error_code is indy.error.ErrorCode.WalletNotFoundError:
                    pass  # This is ok, and expected.
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
            raise WalletConnectionException

    async def disconnect(self):
        """ Close the wallet and set back state to non initialised. """

        if self.__wallet_handle:
            await indy.wallet.close_wallet(self.__wallet_handle)
        self.__initialized = False
        self.__wallet_handle = None

    async def create_and_store_my_did(self):
        if self.__wallet_handle:
            did, verkey = await indy.did.create_and_store_my_did(self.__wallet_handle, "{}")
            return did, verkey
        else:
            raise WalletConnectionException

    @property
    def ephemeral(self):
        return self.__ephemeral

    @property
    def initialized(self):
        return self.__initialized
