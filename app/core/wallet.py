import os
import json
import uuid
import asyncio
import logging
import contextlib
from datetime import datetime, timedelta

import indy
from django.utils.timezone import now, timedelta
from django.conf import settings
from channels.db import database_sync_to_async

from core import AsyncReqResp, WriteOnlyChannel, ReadOnlyChannel
from core.pool import get_pool_handle
from .models import StartedStateMachine


MACHINES_REGISTRY = {}


class InvokableStateMachineMeta(type):

    def __new__(mcs, name, bases, class_dict):
        cls = type.__new__(mcs, name, bases, class_dict)
        MACHINES_REGISTRY[name] = cls
        return cls


class BaseWalletException(Exception):
    error_code = None
    error_message = None

    def __init__(self, error_message=None):
        self.error_message = error_message


WALLET_EXCEPTION_CODES = {}


class WalletExceptionMeta(type):

    def __new__(mcs, name, bases, class_dict):
        cls = type.__new__(mcs, name, bases, class_dict)
        if issubclass(cls, BaseWalletException):
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


class WalletOperationError(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 7


class WalletItemNotFound(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 8


class WalletMachineNotStartedError(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 9


def raise_wallet_exception(error_code, error_message):
    exception_cls = WALLET_EXCEPTION_CODES.get(error_code, None)
    if exception_cls:
        raise exception_cls(error_message)
    else:
        raise RuntimeError(error_message)


async def call_agent(agent_name: str, packet: dict, timeout=settings.REDIS_CONN_TIMEOUT):
    requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
    success, resp = await requests.req(packet, timeout)
    if success:
        error = resp.get('error', None)
        if error:
            raise_wallet_exception(**error)
        else:
            return resp
    else:
        raise AgentTimeOutError()


class WalletConnection:

    def __init__(self, agent_name: str, pass_phrase: str, ephemeral=False):
        self.__agent_name = agent_name
        self.__pass_phrase = pass_phrase
        self.__ephemeral = ephemeral
        self.__is_open = False
        self.__handle = None
        wallet_address = self.make_wallet_address(agent_name)
        self.__log_channel_name = '%s:log' % uuid.uuid4().hex
        self.__log_channel = None
        cfg = {"id": wallet_address}
        cfg.update(settings.INDY.get('WALLET_SETTINGS', {}).get('config', {}))
        cred = {"key": self.__pass_phrase}
        cred.update(settings.INDY.get('WALLET_SETTINGS', {}).get('credentials', {}))
        self.__wallet_config = json.dumps(cfg)
        self.__wallet_credentials = json.dumps(cred)

    @contextlib.contextmanager
    def enter(self):
        if self.__handle:
            try:
                yield self.__handle
            except indy.error.IndyError as e:
                if e.error_code is indy.error.ErrorCode.WalletNotFoundError:
                    raise WalletNotCreated(error_message=e.message)
                elif e.error_code is indy.error.ErrorCode.WalletAccessFailed:
                    raise WalletAccessDenied(error_message=e.message)
                elif e.error_code is indy.error.ErrorCode.WalletAlreadyExistsError:
                    raise WalletAlreadyExists(error_message=e.message)
                elif e.error_code is indy.error.ErrorCode.WalletItemNotFound:
                    raise WalletItemNotFound(error_message=e.message)
                else:
                    raise WalletOperationError(error_message=e.message)
        else:
            raise WalletIsNotOpen(error_message='Open wallet at first')

    @property
    def log_channel_name(self):
        return self.__log_channel_name

    async def log(self, message: str, details: dict=None):
        if self.__log_channel is None:
            self.__log_channel = await WriteOnlyChannel.create(self.__log_channel_name)
        await self.__log_channel.write([message, details])

    async def error(self, error_message: str):
        await self.log(message='Error', details=dict(error_message=error_message))

    @property
    def agent_name(self):
        return self.__agent_name

    def check_credentials(self, agent_name: str, pass_phrase: str):
        if not self.__handle:
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
        if self.__handle:
            await indy.wallet.close_wallet(self.__handle)
        try:
            self.__handle = await indy.wallet.open_wallet(
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
                raise WalletOperationError(error_message=e.message)

    async def close(self):
        """ Close the wallet and set back state to non initialised. """
        if self.__handle:
            await indy.wallet.close_wallet(self.__handle)
        if self.__log_channel and not self.__log_channel.is_closed:
            await self.__log_channel.close()
        self.__is_open = False
        self.__handle = None

    async def delete(self):
        if self.__handle:
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
            if self.__handle:
                await indy.wallet.close_wallet(self.__handle)
            self.__handle = await indy.wallet.open_wallet(
                self.__wallet_config,
                self.__wallet_credentials
            )
            self.__is_open = True
        except Exception as e:
            logging.error(str(e))
            logging.error("Could not open wallet!")
            raise WalletConnectionException(error_message=str(e))

    async def create_and_store_my_did(self, seed: str=None):
        with self.enter():
            options = dict()
            if seed:
                options['seed'] = seed
            did, verkey = await indy.did.create_and_store_my_did(self.__handle, json.dumps(options))
            return did, verkey

    async def store_their_did(self, did: str, verkey: str=None):
        with self.enter():
            identity = dict(did=did)
            if verkey:
                identity['verkey'] = verkey
            identity_str = json.dumps(identity)
            await indy.did.store_their_did(self.__handle, identity_str)

    async def set_did_metadata(self, did: str, metadata: dict=None):
        with self.enter():
            metadata_str = json.dumps(metadata) if metadata else ''
            await indy.did.set_did_metadata(self.__handle, did, metadata_str)

    async def list_my_dids_with_meta(self):
        with self.enter():
            list_as_str = await indy.did.list_my_dids_with_meta(self.__handle)
            return json.loads(list_as_str)

    async def get_did_metadata(self, did):
        with self.enter():
            metadata_str = await indy.did.get_did_metadata(self.__handle, did)
            if metadata_str:
                return json.loads(metadata_str)
            else:
                return None

    async def key_for_local_did(self, did):
        with self.enter():
            vk = await indy.did.key_for_local_did(self.__handle, did)
            return vk

    async def create_key(self):
        with self.enter():
            verkey = await indy.did.create_key(self.__handle, "{}")
            return verkey

    async def add_wallet_record(self, type_: str, id_: str, value: str, tags: dict=None):
        with self.enter():
            tags_ = tags or {}
            await indy.non_secrets.add_wallet_record(self.__handle, type_, id_, value, json.dumps(tags_))

    async def get_wallet_record(self, type_: str, id_: str, options: dict=None):
        with self.enter():
            options_ = options or {}
            json_str = await indy.non_secrets.get_wallet_record(self.__handle, type_, id_, json.dumps(options_))
            return json.loads(json_str)['value']

    async def update_wallet_record_value(self, type_: str, id_: str, value: str):
        with self.enter():
            await indy.non_secrets.update_wallet_record_value(self.__handle, type_, id_, value)

    async def get_pairwise(self, their_did):
        with self.enter():
            info_str = await indy.pairwise.get_pairwise(self.__handle, their_did)
            info = json.loads(info_str)
            if info['metadata']:
                info['metadata'] = json.loads(info['metadata'])
            return info

    async def create_pairwise(self, their_did: str, my_did: str, metadata: dict=None):
        with self.enter():
            metadata = metadata or {}
            await indy.pairwise.create_pairwise(self.__handle, their_did, my_did, json.dumps(metadata))

    async def list_pairwise(self):
        with self.enter():
            pairwise_list_str = await indy.pairwise.list_pairwise(self.__handle)
            pairwise_list = json.loads(pairwise_list_str)
            result = []
            for s in pairwise_list:
                item = json.loads(s)
                item['metadata'] = json.loads(item['metadata']) if item['metadata'] else None
                result.append(item)
            return result

    async def pack_message(self, message, their_ver_key, my_ver_key=None):
        with self.enter():
            if their_ver_key is not list:
                their_ver_keys_list = [their_ver_key]
            else:
                their_ver_keys_list = their_ver_key
            wire_message = await indy.crypto.pack_message(self.__handle, message, their_ver_keys_list, my_ver_key)
            return wire_message

    async def unpack_message(self, wire_msg_bytes: bytes):
        with self.enter():
            unpacked = await indy.crypto.unpack_message(self.__handle, wire_msg_bytes)
            if isinstance(unpacked, str):
                unpacked_str = unpacked
            else:
                unpacked_str = unpacked.decode('utf-8')
            unpacked = json.loads(unpacked_str)
            return unpacked

    async def crypto_sign(self, verkey: str, sig_data_bytes: bytes):
        with self.enter():
            signature_bytes = await indy.crypto.crypto_sign(self.__handle, verkey, sig_data_bytes)
            return signature_bytes

    async def build_nym_request(self, self_did: str, target_did: str, ver_key: str, role: str, alias: str=None):
        # Do not delete: Open pool for preparing pool environment
        await get_pool_handle()
        with self.enter():
            nym_transaction_request = await indy.ledger.build_nym_request(
                submitter_did=self_did,
                target_did=target_did,
                ver_key=ver_key,
                alias=alias,
                role=role
            )
            return json.loads(nym_transaction_request)

    async def build_schema_request(self, self_did: str, name: str, version: str, attributes):
        # Do not delete: Open pool for preparing pool environment
        await get_pool_handle()
        with self.enter():
            attributes = json.dumps(attributes)
            issuer_schema_id, issuer_schema_json = await indy.anoncreds.issuer_create_schema(
                self_did, name, version, attributes
            )
            schema_request = await indy.ledger.build_schema_request(self_did, issuer_schema_json)
            return json.loads(schema_request), json.loads(issuer_schema_json)

    async def issuer_create_credential_def(
            self, self_did: str, schema_id: str, tag: str, support_revocation: bool
    ):
        # Do not delete: Open pool for preparing pool environment
        pool_handle = await get_pool_handle()
        with self.enter():
            get_schema_request = await indy.ledger.build_get_schema_request(self_did, schema_id)
            get_schema_response = await indy.ledger.submit_request(pool_handle, get_schema_request)
            _, schema_json_str = await indy.ledger.parse_get_schema_response(get_schema_response)

            config_json = json.dumps({"support_revocation": support_revocation})
            cred_def_id, cred_def_json = await indy.anoncreds.issuer_create_and_store_credential_def(
                wallet_handle=self.__handle,
                issuer_did=self_did,
                schema_json=schema_json_str,
                tag=tag,
                signature_type='CL',
                config_json=config_json
            )
            cred_def_request = await indy.ledger.build_cred_def_request(self_did, cred_def_json)
            return cred_def_id, json.loads(cred_def_json), json.loads(cred_def_request), json.loads(schema_json_str)

    async def sign_and_submit_request(self, self_did: str, request_json):
        # Do not delete: Open pool for preparing pool environment
        pool = await get_pool_handle()
        with self.enter():
            nym_transaction_response = await indy.ledger.sign_and_submit_request(
                pool_handle=pool,
                wallet_handle=self.__handle,
                submitter_did=self_did,
                request_json=json.dumps(request_json)
            )
            return json.loads(nym_transaction_response)

    async def issuer_create_credential_offer(self, cred_def_id: str):
        # Do not delete: Open pool for preparing pool environment
        await get_pool_handle()
        with self.enter():
            cred_offer_json = await indy.anoncreds.issuer_create_credential_offer(self.__handle, cred_def_id)
            return json.loads(cred_offer_json)

    async def prover_create_master_secret(self, master_secret_name: str):
        # Do not delete: Open pool for preparing pool environment
        await get_pool_handle()
        with self.enter():
            link_secret_id = await indy.anoncreds.prover_create_master_secret(self.__handle, master_secret_name)
            return link_secret_id

    async def prover_create_credential_req(self, prover_did: str, cred_offer: dict, cred_def: dict, master_secret_id: str):
        # Do not delete: Open pool for preparing pool environment
        await get_pool_handle()
        with self.enter():
            cred_req_json, cred_req_metadata_json = await indy.anoncreds.prover_create_credential_req(
                wallet_handle=self.__handle,
                prover_did=prover_did,
                cred_offer_json=json.dumps(cred_offer),
                cred_def_json=json.dumps(cred_def),
                master_secret_id=master_secret_id
            )
            return json.loads(cred_req_json), json.loads(cred_req_metadata_json)

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
    COMMAND_ADD_WALLET_RECORD = 'add_wallet_record'
    COMMAND_GET_WALLET_RECORD = 'get_wallet_record'
    COMMAND_LIST_MY_DIDS_WITH_META = 'list_my_dids_with_meta'
    COMMAND_CREATE_AND_STORE_MY_DID = 'create_and_store_my_did'
    COMMAND_KEY_FOR_LOCAL_DID = 'key_for_local_did'
    COMMAND_UPDATE_WALLET_RECORD = 'update_wallet_record'
    COMMAND_GET_PAIRWISE = 'get_pairwise'
    COMMAND_LIST_PAIRWISE = 'list_pairwise'
    COMMAND_PACK_MESSAGE = 'pack_message'
    COMMAND_UNPACK_MESSAGE = 'unpack_message'
    COMMAND_START_STATE_MACHINE = 'start_state_machine'
    COMMAND_INVOKE_STATE_MACHINE = 'invoke_state_machine'
    COMMAND_ACCESS_LOG = 'access_log'
    COMMAND_WRITE_LOG = 'write_log'
    COMMAND_BUILD_NYM_REQUEST = 'build_nym_request'
    COMMAND_SIGN_AND_SUBMIT_REQUEST = 'sign_and_submit_request'
    COMMAND_BUILD_SCHEMA_REQUEST = 'build_schema_request'
    COMMAND_ISSUER_CREATE_CRED_DEF = 'issuer_create_credential_def'
    COMMAND_ISSUER_CREATE_CRED_OFFER = 'issuer_create_credential_offer'
    COMMAND_PROVER_CREATE_MASTER_SECRET = 'prover_create_master_secret'
    COMMAND_PROVER_CREATE_CRED_REQ = 'prover_create_credential_req'
    TIMEOUT = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_REQUEST']
    TIMEOUT_START = settings.INDY['WALLET_SETTINGS']['TIMEOUTS']['AGENT_START']

    @classmethod
    async def ensure_agent_is_running(cls, agent_name: str, timeout=TIMEOUT_START):
        until_to = datetime.now() + timedelta(seconds=timeout)
        if await cls.ping(agent_name):
            return
        else:
            os.system('nohup python /app/manage.py run_wallet_agent %s &' % agent_name)
            while datetime.now() <= until_to:
                if await cls.ping(agent_name, 1):
                    return
                else:
                    asyncio.sleep(1)
            raise AgentTimeOutError('Agent is not running')

    @classmethod
    async def ensure_agent_is_open(cls, agent_name: str, pass_phrase: str):
        await cls.ensure_agent_is_running(agent_name)
        await cls.open(agent_name, pass_phrase)

    @classmethod
    async def ping(cls, agent_name: str, timeout=TIMEOUT):
        ping = dict(
            command=cls.COMMAND_PING,
            marker=uuid.uuid4().hex
        )
        try:
            pong = await call_agent(agent_name, ping, timeout)
            return pong['command'] == cls.COMMAND_PONG and pong['marker'] == ping['marker']
        except AgentTimeOutError:
            return False

    @classmethod
    async def is_open(cls, agent_name: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_IS_OPEN,
        )
        try:
            resp = await call_agent(agent_name, packet, timeout)
            return resp.get('ret')
        except AgentTimeOutError:
            return False

    @classmethod
    async def open(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_OPEN,
            pass_phrase=pass_phrase,
        )
        await call_agent(agent_name, packet, timeout)

    @classmethod
    async def close(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_CLOSE,
            pass_phrase=pass_phrase,
        )
        await call_agent(agent_name, packet, timeout)

    @classmethod
    async def create_and_store_my_did(cls, agent_name: str, pass_phrase: str, seed: str=None, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_CREATE_AND_STORE_MY_DID,
            pass_phrase=pass_phrase,
            kwargs=dict(seed=seed)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def create_key(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_CREATE_KEY,
            pass_phrase=pass_phrase,
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def key_for_local_did(cls, agent_name: str, pass_phrase: str, did, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_KEY_FOR_LOCAL_DID,
            pass_phrase=pass_phrase,
            kwargs=dict(did=did)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def list_my_dids_with_meta(cls,  agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_LIST_MY_DIDS_WITH_META,
            pass_phrase=pass_phrase,
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def add_wallet_record(cls, agent_name: str, pass_phrase: str, type_: str, id_: str, value: str,
                                tags: dict=None, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_ADD_WALLET_RECORD,
            pass_phrase=pass_phrase,
            kwargs=dict(type_=type_, id_=id_, value=value, tags=tags)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def get_wallet_record(cls, agent_name: str, pass_phrase: str, type_: str, id_: str, options: dict=None,
                                timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_GET_WALLET_RECORD,
            pass_phrase=pass_phrase,
            kwargs=dict(type_=type_, id_=id_, options=options)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def update_wallet_record_value(cls, agent_name: str, pass_phrase: str, type_: str, id_: str, value: str,
                                         timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_UPDATE_WALLET_RECORD,
            pass_phrase=pass_phrase,
            kwargs=dict(type_=type_, id_=id_, value=value)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def get_pairwise(cls, agent_name: str, pass_phrase: str, their_did: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_GET_PAIRWISE,
            pass_phrase=pass_phrase,
            kwargs=dict(their_did=their_did)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def list_pairwise(cls, agent_name: str, pass_phrase: str, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_LIST_PAIRWISE,
            pass_phrase=pass_phrase,
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def pack_message(cls, agent_name: str, message, their_ver_key, my_ver_key=None, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_PACK_MESSAGE,
            kwargs=dict(message=message, their_ver_key=their_ver_key, my_ver_key=my_ver_key)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret').encode('utf-8')

    @classmethod
    async def unpack_message(cls, agent_name: str, wire_msg_bytes: bytes, timeout=TIMEOUT):
        packet = dict(
            command=cls.COMMAND_UNPACK_MESSAGE,
            kwargs=dict(wire_msg_bytes=wire_msg_bytes.decode('utf-8'))
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def build_nym_request(
            cls, agent_name: str, pass_phrase: str, self_did: str, target_did: str, ver_key: str,
            role: str, alias: str = None, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_BUILD_NYM_REQUEST,
            pass_phrase=pass_phrase,
            kwargs=dict(self_did=self_did, target_did=target_did, ver_key=ver_key, role=role, alias=alias)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def build_schema_request(
            cls, agent_name: str, pass_phrase: str, self_did: str, name: str,
            version: str, attributes, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_BUILD_SCHEMA_REQUEST,
            pass_phrase=pass_phrase,
            kwargs=dict(self_did=self_did, name=name, version=version, attributes=attributes)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def issuer_create_credential_def(
            cls, agent_name: str, pass_phrase: str, self_did: str, schema_id: str, tag: str,
            support_revocation: bool, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_ISSUER_CREATE_CRED_DEF,
            pass_phrase=pass_phrase,
            kwargs=dict(self_did=self_did, schema_id=schema_id, tag=tag, support_revocation=support_revocation)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def sign_and_submit_request(
            cls, agent_name: str, pass_phrase: str, self_did: str, request_json, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_SIGN_AND_SUBMIT_REQUEST,
            pass_phrase=pass_phrase,
            kwargs=dict(self_did=self_did, request_json=json.dumps(request_json))
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def start_state_machine(cls, agent_name: str, machine_class, machine_id: str, ttl: int=300, **setup):
        await cls.ensure_agent_is_running(agent_name)
        packet = dict(
            command=cls.COMMAND_START_STATE_MACHINE,
            kwargs=dict(machine_class=machine_class.__name__, machine_id=machine_id, ttl=ttl, **setup)
        )
        resp = await call_agent(agent_name, packet)
        return resp.get('ret')

    @classmethod
    async def invoke_state_machine(cls, agent_name: str, id_: str, content_type: str, data):
        await cls.ensure_agent_is_running(agent_name)
        if isinstance(data, bytes):
            wire_msg_utf = data.decode('utf-8')
            is_bytes = True
        else:
            wire_msg_utf = data
            is_bytes = False
        packet = dict(
            command=cls.COMMAND_INVOKE_STATE_MACHINE,
            kwargs=dict(id_=id_, content_type=content_type, data=wire_msg_utf, is_bytes=is_bytes)
        )
        resp = await call_agent(agent_name, packet)
        return resp.get('ret')

    @classmethod
    async def issuer_create_credential_offer(
            cls, agent_name: str, pass_phrase: str, cred_def_id: str, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_ISSUER_CREATE_CRED_OFFER,
            pass_phrase=pass_phrase,
            kwargs=dict(cred_def_id=cred_def_id)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def prover_create_master_secret(
            cls, agent_name: str, pass_phrase: str, master_secret_name: str, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_PROVER_CREATE_MASTER_SECRET,
            pass_phrase=pass_phrase,
            kwargs=dict(master_secret_name=master_secret_name)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def prover_create_credential_req(
            cls,  agent_name: str, pass_phrase: str, prover_did: str, cred_offer: dict,
            cred_def: dict, master_secret_id: str, timeout=TIMEOUT
    ):
        packet = dict(
            command=cls.COMMAND_PROVER_CREATE_CRED_REQ,
            pass_phrase=pass_phrase,
            kwargs=dict(prover_did=prover_did, cred_offer=cred_offer, cred_def=cred_def, master_secret_id=master_secret_id)
        )
        resp = await call_agent(agent_name, packet, timeout)
        return resp.get('ret')

    @classmethod
    async def access_log(cls, agent_name: str, pass_phrase: str):
        await cls.ensure_agent_is_running(agent_name)
        packet = dict(
            command=cls.COMMAND_ACCESS_LOG,
            pass_phrase=pass_phrase
        )
        resp = await call_agent(agent_name, packet)
        channel_name = resp.get('ret')
        return await ReadOnlyChannel.create(channel_name)

    @classmethod
    async def write_log(cls, agent_name: str, pass_phrase: str, message: str, details: dict):
        await cls.ensure_agent_is_running(agent_name)
        packet = dict(
            command=cls.COMMAND_WRITE_LOG,
            pass_phrase=pass_phrase,
            kwargs=dict(message=message, details=details)
        )
        await call_agent(agent_name, packet)

    @classmethod
    async def process(cls, agent_name: str):
        address = WalletConnection.make_wallet_address(agent_name)
        logging.info('Wallet Agent "%s" is started' % agent_name)
        listener = AsyncReqResp(address)
        await listener.start_listening()
        wallet__ = None
        machines = {}
        machines_die_time = {}

        def check_access_denied(pass_phrase_):
            if not wallet__.check_credentials(agent_name, pass_phrase_):
                raise WalletAccessDenied()
        pass

        async def invoke_state_machine(id_: str, content_type: str, data):
            nonlocal machines
            if (wallet__ is None) or (not wallet__.is_open):
                raise WalletIsNotOpen()
            instance, write_channel = machines.get(id_, (None, None))
            if not instance:
                instance = await database_sync_to_async(try_load_started_machine)(id_)
                if instance:
                    # Wrap state machine into Future
                    uid = uuid.uuid4().hex
                    write_channel = await WriteOnlyChannel.create(uid)
                    read_channel = await ReadOnlyChannel.create(uid)

                    async def processor(machine, read_chan: ReadOnlyChannel, wallet):
                        try:
                            try:
                                while True:
                                    s, d = await read_chan.read(timeout=None)
                                    if s:
                                        content_type_, data_descr = d
                                        is_bytes_ = data_descr['is_bytes']
                                        data_ = data_descr['data']
                                        if is_bytes_:
                                            data_ = data_.encode()
                                        await machine.invoke(content_type_, data_, wallet)
                                    else:
                                        break
                            except Exception as e:
                                if e.__class__.__name__ == 'MachineIsDone':
                                    pass
                                else:
                                    logging.exception('State Machine terminated with exception')
                        finally:
                            await read_chan.close()
                    pass

                    fut = asyncio.ensure_future(
                        processor(instance, read_channel, wallet__)
                    )
                    machines[id_] = (fut, write_channel)
                else:
                    raise WalletMachineNotStartedError('MachineID: %s' % id_)
            if isinstance(data, bytes):
                data_descr = dict(is_bytes=True, data=data.decode())
            else:
                data_descr = dict(is_bytes=False, data=data)
            await write_channel.write((content_type, data_descr))
        pass

        async def clean_done_machines():
            while True:
                await asyncio.sleep(30)
                for id_, descr_ in machines.items():
                    f_, ch_ = descr_
                    if (id_ in machines_die_time) and (now() > machines_die_time[id_]):
                        f_.cancel()
                    if f_.done() or f_.cancelled():
                        del machines[id_]
                        await database_sync_to_async(machine_stopped)(id_)
                        if id_ in machines_die_time:
                            del machines_die_time[id_]
                    pass
                pass
        pass
        machines_cleaner_task = asyncio.ensure_future(clean_done_machines())

        try:
            try:
                while True:
                    req, chan = await listener.wait_req()
                    try:
                        logging.debug('Received request: "%s"' % repr(req))
                        command = req['command']
                        pass_phrase = req.get('pass_phrase', None)
                        kwargs = req.get('kwargs', {})
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
                                    ret = await wallet__.create_and_store_my_did(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_IS_OPEN:
                                ret = wallet__ is not None and wallet__.is_open
                                await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_ADD_WALLET_RECORD:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.add_wallet_record(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_GET_WALLET_RECORD:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.get_wallet_record(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_UPDATE_WALLET_RECORD:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.update_wallet_record_value(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_KEY_FOR_LOCAL_DID:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.key_for_local_did(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_GET_PAIRWISE:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.get_pairwise(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_LIST_PAIRWISE:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.list_pairwise()
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_PACK_MESSAGE:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    ret = await wallet__.pack_message(**kwargs)
                                    ret = ret.decode('utf-8')
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_UNPACK_MESSAGE:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    kwargs['wire_msg_bytes'] = kwargs['wire_msg_bytes'].encode('utf-8')
                                    ret = await wallet__.unpack_message(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_START_STATE_MACHINE:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    ttl = kwargs.pop('ttl')
                                    await database_sync_to_async(machine_started)(**kwargs)
                                    machine_id = kwargs['machine_id']
                                    machines_die_time[machine_id] = now() + timedelta(seconds=ttl)
                                    await chan.write(dict(ret=True))
                            elif command == cls.COMMAND_INVOKE_STATE_MACHINE:
                                try:
                                    is_bytes = kwargs.pop('is_bytes')
                                    if is_bytes:
                                        kwargs['data'] = kwargs['data'].encode('utf-8')
                                    await invoke_state_machine(**kwargs)
                                except Exception as e:
                                    req['error'] = dict(error_code=WalletOperationError.error_code, error_message=str(e))
                                await chan.write(dict(ret=True))
                            elif command == cls.COMMAND_ACCESS_LOG:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = wallet__.log_channel_name
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_WRITE_LOG:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.log(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_LIST_MY_DIDS_WITH_META:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.list_my_dids_with_meta()
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_BUILD_NYM_REQUEST:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.build_nym_request(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_SIGN_AND_SUBMIT_REQUEST:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    kwargs['request_json'] = json.loads(kwargs['request_json'])
                                    ret = await wallet__.sign_and_submit_request(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_BUILD_SCHEMA_REQUEST:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.build_schema_request(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_ISSUER_CREATE_CRED_DEF:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.issuer_create_credential_def(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_ISSUER_CREATE_CRED_OFFER:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.issuer_create_credential_offer(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_PROVER_CREATE_MASTER_SECRET:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.prover_create_master_secret(**kwargs)
                                    await chan.write(dict(ret=ret))
                            elif command == cls.COMMAND_PROVER_CREATE_CRED_REQ:
                                if wallet__ is None:
                                    raise WalletIsNotOpen()
                                else:
                                    check_access_denied(pass_phrase)
                                    ret = await wallet__.prover_create_credential_req(**kwargs)
                                    await chan.write(dict(ret=ret))
                        except BaseWalletException as e:
                            req['error'] = dict(error_code=e.error_code, error_message=e.error_message)
                            await chan.write(req)
                        except Exception as e:
                            req['error'] = dict(error_code=WalletOperationError.error_code, error_message=str(e))
                            await chan.write(req)
                    finally:
                        await chan.close()
            finally:
                # terminate all active machines
                machines_cleaner_task.cancel()
                for f, ch in machines.values():
                    f.cancel()
                    await ch.close()
                if wallet__ and wallet__.is_open:
                    await wallet__.close()
        finally:
            await listener.stop_listening()
            logging.debug('Wallet Agent "%s" is stopped' % agent_name)


def try_load_started_machine(id_: str):
    descr = StartedStateMachine.objects.filter(machine_id=id_).first()
    if descr:
        cls = MACHINES_REGISTRY.get(descr.machine_class_name, None)
        if cls:
            return cls(id_)
    return None


def machine_started(machine_id: str, machine_class: str, **setup):
    StartedStateMachine.objects.get_or_create(machine_id=machine_id, machine_class_name=machine_class)
    instance = try_load_started_machine(machine_id)
    instance.setup(**setup)


def machine_stopped(machine_id: str):
    StartedStateMachine.objects.filter(machine_id=machine_id).all().delete()
