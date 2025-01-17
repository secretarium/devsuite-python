import asyncio
import logging
from secretarium_connector import SCP, SCPOptions, Key


logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

async def main():

    print(f"TEST: Starting tests")
    key = await Key.createKey()
    scp = SCP(options=SCPOptions(gatewayTimeout=0))
    scp.onError(lambda message: print(f"SCP Error: {message}"))

    try:
        # context = await scp.connect("wss://gimli4.node.secretarium.org:9430", key)
        # context = await scp.connect("wss://gimli4.node.secretarium.org:5001", key)
        await scp.connect("wss://klave-dev.secretarium.org", key)
        # await scp.connect("wss://gimli4.node.secretarium.org:20000", key)
        tx = scp.newTx("wasm-manager", "version", None, '{}')
        
        print(f"TEST: Registering listeners")
        tx.onError(lambda message: print(f"LMB Error: {message}"))
        tx.onExecuted(lambda: print(f"LMB Executed 1: Should not show"))
        tx.onResult(lambda message: print(f"LMB Result 1: {message}"))
        tx.onResult(lambda message, r: print(f"LMB Result 2: {message['version']['core_version']['major']}  || {r}"))

        print(f"TEST: Sending data")
        coucou = await tx.send()
        print(f"TEST: Waiting for results...")
        print(f"Awaited result: {coucou['version']}")

        try:
            # Keep the client running indefinitely
            while True:
                await asyncio.sleep(1)  # Prevents blocking the event loop
        except asyncio.CancelledError:
            print("Client is stopping...")
        finally:
            await scp.close()

    except Exception as e:
        print(f"Global Error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Application interrupted by user.")
    except Exception as e:
        print(f"Main Error: {e}")