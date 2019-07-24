import asyncio
import threading


def run_async(coro, timeout=5):
    return Scheduler.run_async(coro, timeout)


class Scheduler:

    __instance = None

    def __init__(self):
        if self.__instance is not None:
            raise RuntimeError()
        else:
            self.__loop = asyncio.new_event_loop()
            self.__thread = threading.Thread(target=self.__run_event_loop_in_thread, args=(self.__loop,))
            self.__thread.daemon = True
            self.__thread.start()

    @classmethod
    def run_async(cls, coro, timeout=5):
        assert asyncio.coroutines.iscoroutine(coro)
        fut = asyncio.run_coroutine_threadsafe(coro, loop=cls.__get_instance().__loop)
        return fut.result(timeout)

    @staticmethod
    def __run_event_loop_in_thread(loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()

    @classmethod
    def __get_loop(cls):
        return cls.__get_instance().__loop

    @classmethod
    def __get_instance(cls):
        if not cls.__instance:
            cls.__instance = Scheduler()
        return cls.__instance
