import uuid
import asyncio

import pytest

from core.base import *


@pytest.mark.asyncio
async def test_req_resp_sane():
    reqresp = AsyncReqResp('test-address')
    ping = {'marker': uuid.uuid4().hex}

    success, resp = await reqresp.req(ping)
    assert success is False
    assert resp is None

    async def ponger():
        await reqresp.start_listening()
        try:
            data, chan = await reqresp.wait_req()
            await chan.write(data)
        finally:
            await reqresp.start_listening()
    try:
        f = asyncio.ensure_future(ponger())
        asyncio.sleep(1)

        success, resp = await reqresp.req(ping)
        assert success is True
        assert resp == ping
    finally:
        f.cancel()
