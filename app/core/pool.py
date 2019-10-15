import json

from indy import pool
from indy.error import IndyError, ErrorCode
from django.conf import settings


POOL_HANDLE = None


async def get_pool_handle():
    global POOL_HANDLE
    if POOL_HANDLE is None:
        POOL_HANDLE = await open_pool()
    return POOL_HANDLE


async def open_pool():
    await pool.set_protocol_version(settings.INDY['PROTOCOL_VERSION'])
    pool_config = json.dumps({'genesis_txn': settings.INDY['GENESIS_TXN_FILE_PATH']})
    try:
        await pool.create_pool_ledger_config(config_name=settings.INDY['POOL_NAME'], config=pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_handle = await pool.open_pool_ledger(config_name=settings.INDY['POOL_NAME'], config=None)
    return pool_handle


async def close_pool(pool_handle):
    await pool.close_pool_ledger(pool_handle)
    await pool.delete_pool_ledger_config(settings.INDY['POOL_NAME'])
