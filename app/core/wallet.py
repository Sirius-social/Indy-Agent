import os
import json
import uuid
import asyncio
import logging
from datetime import datetime, timedelta

import indy
from django.conf import settings
from channels.db import database_sync_to_async

from core import AsyncReqResp, WriteOnlyChannel, ReadOnlyChannel
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


class WalletMachineNotStartedError(BaseWalletException, metaclass=WalletExceptionMeta):
    error_code = 8


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
        self.__handle = None
        wallet_address = self.make_wallet_address(agent_name)
        cfg = {"id": wallet_address}
        cfg.update(settings.INDY.get('WALLET_SETTINGS', {}).get('config', {}))
        cred = {"key": self.__pass_phrase}
        cred.update(settings.INDY.get('WALLET_SETTINGS', {}).get('credentials', {}))
        self.__wallet_config = json.dumps(cfg)
        self.__wallet_credentials = json.dumps(cred)

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
                raise e

    async def close(self):
        """ Close the wallet and set back state to non initialised. """
        if self.__handle:
            await indy.wallet.close_wallet(self.__handle)
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

    async def create_and_store_my_did(self):
        if self.__handle:
            try:
                did, verkey = await indy.did.create_and_store_my_did(self.__handle, "{}")
                return did, verkey
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def set_did_metadata(self, did: str, metadata: dict=None):
        if self.__handle:
            metadata_str = json.dumps(metadata) if metadata else ''
            try:
                await indy.did.set_did_metadata(self.__handle, did, metadata_str)
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def get_did_metadata(self, did):
        if self.__handle:
            try:
                metadata_str = await indy.did.get_did_metadata(self.__handle, did)
                if metadata_str:
                    return json.loads(metadata_str)
                else:
                    return None
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def key_for_local_did(self, did):
        if self.__handle:
            try:
                vk = await indy.did.key_for_local_did(self.__handle, did)
                return vk
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def create_key(self):
        if self.__handle:
            try:
                verkey = await indy.did.create_key(self.__handle, "{}")
                return verkey
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def add_wallet_record(self, type_: str, id_: str, value: str, tags: dict=None):
        if self.__handle:
            tags_ = tags or {}
            try:
                await indy.non_secrets.add_wallet_record(self.__handle, type_, id_, value, json.dumps(tags_))
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def get_wallet_record(self, type_: str, id_: str, options: dict=None):
        if self.__handle:
            options_ = options or {}
            try:
                json_str = await indy.non_secrets.get_wallet_record(self.__handle, type_, id_, json.dumps(options_))
                return json.loads(json_str)['value']
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
        else:
            raise WalletIsNotOpen()

    async def update_wallet_record_value(self, type_: str, id_: str, value: str):
        if self.__handle:
            try:
                await indy.non_secrets.update_wallet_record_value(self.__handle, type_, id_, value)
            except indy.error.IndyError as e:
                raise WalletOperationError(e.message)
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
    COMMAND_ADD_WALLET_RECORD = 'add_wallet_record'
    COMMAND_GET_WALLET_RECORD = 'get_wallet_record'
    COMMAND_CREATE_AND_STORE_MY_DID = 'create_and_store_my_did'
    COMMAND_KEY_FOR_LOCAL_DID = 'key_for_local_did'
    COMMAND_UPDATE_WALLET_RECORD = 'update_wallet_record'
    COMMAND_START_STATE_MACHINE = 'start_state_machine'
    COMMAND_INVOKE_STATE_MACHINE = 'invoke_state_machine'
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
    async def key_for_local_did(cls, agent_name: str, pass_phrase: str, did, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_KEY_FOR_LOCAL_DID,
            pass_phrase=pass_phrase,
            kwargs=dict(did=did)
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
    async def add_wallet_record(cls, agent_name: str, pass_phrase: str, type_: str, id_: str, value: str,
                                tags: dict=None, timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_ADD_WALLET_RECORD,
            pass_phrase=pass_phrase,
            kwargs=dict(type_=type_, id_=id_, value=value, tags=tags)
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
    async def get_wallet_record(cls, agent_name: str, pass_phrase: str, type_: str, id_: str, options: dict=None,
                                timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_GET_WALLET_RECORD,
            pass_phrase=pass_phrase,
            kwargs=dict(type_=type_, id_=id_, options=options)
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
    async def update_wallet_record_value(cls, agent_name: str, pass_phrase: str, type_: str, id_: str, value: str,
                                         timeout=TIMEOUT):
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        packet = dict(
            command=cls.COMMAND_UPDATE_WALLET_RECORD,
            pass_phrase=pass_phrase,
            kwargs=dict(type_=type_, id_=id_, value=value)
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
    async def start_state_machine(cls, agent_name: str, pass_phrase: str, machine_class, machine_id: str):
        await cls.ensure_agent_is_open(agent_name, pass_phrase)
        packet = dict(
            command=cls.COMMAND_START_STATE_MACHINE,
            pass_phrase=pass_phrase,
            kwargs=dict(machine_class=machine_class.__name__, machine_id=machine_id)
        )
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        success, resp = await requests.req(packet)
        if success:
            error = resp.get('error', None)
            if error:
                raise_wallet_exception(**error)
            else:
                return resp['ret']
        else:
            raise AgentTimeOutError()

    @classmethod
    async def invoke_state_machine(cls, agent_name: str, id_: str, content_type: str, data):
        await cls.ensure_agent_is_running(agent_name)
        packet = dict(
            command=cls.COMMAND_INVOKE_STATE_MACHINE,
            kwargs=dict(id_=id_, content_type=content_type, data=data)
        )
        requests = AsyncReqResp(WalletConnection.make_wallet_address(agent_name))
        success, resp = await requests.req(packet)
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
        machines = {}

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
                                        content_type_, data_ = d
                                        await machine.invoke(content_type_, data_, wallet)
                                    else:
                                        break
                            except:
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
            await write_channel.write((content_type, data))
        pass

        async def clean_done_machines():
            while True:
                await asyncio.sleep(60)
                for id_, descr_ in machines.items():
                    f_, ch_ = descr_
                    if f_.done():
                        del machines[id_]
        pass
        machines_cleaner_task = asyncio.ensure_future(clean_done_machines())

        try:
            try:
                while True:
                    req, chan = await listener.wait_req()
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
                                ret = await wallet__.create_and_store_my_did()
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
                        elif command == cls.COMMAND_START_STATE_MACHINE:
                            if wallet__ is None:
                                raise WalletIsNotOpen()
                            else:
                                check_access_denied(pass_phrase)
                                await database_sync_to_async(machine_started)(**kwargs)
                                await chan.write(dict(ret=True))
                        elif command == cls.COMMAND_INVOKE_STATE_MACHINE:
                            try:
                                await invoke_state_machine(**kwargs)
                            except Exception as e:
                                req['error'] = dict(error_code=WalletOperationError.error_code, error_message=str(e))
                            await chan.write(dict(ret=True))
                    except BaseWalletException as e:
                        req['error'] = dict(error_code=e.error_code, error_message=e.error_message)
                        await chan.write(req)
                    except Exception as e:
                        req['error'] = dict(error_code=WalletOperationError.error_code, error_message=str(e))
                        await chan.write(req)
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


def machine_started(machine_id: str, machine_class: str):
    StartedStateMachine.objects.get_or_create(machine_id=machine_id, machine_class_name=machine_class)
