def make_wallet_wired_messages_channel_name(uid: str):
    return '%s/wired-messages' % uid


async def handle_wired_message(agent_name: str, pass_phrase: str, content_type: str, wired: dict):
    pass
