import asyncio

from django.core.management.base import BaseCommand


from core.wallet import WalletAgent


class Command(BaseCommand):

    help = 'Run Wallet agent'

    def add_arguments(self, parser):
        parser.add_argument('agent_name', type=str)

    def handle(self, *args, **options):
        agent_name = options['agent_name']
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.__background_task(agent_name))
        loop.close()

    @staticmethod
    async def __background_task(agent_name):
        # If another agent is running then exit
        ping = await WalletAgent.ping(agent_name)
        if not ping:
            await WalletAgent.process(agent_name)
        pass
