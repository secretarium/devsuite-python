import asyncio
import logging
from secretarium_connector import SCP, Key


logging.basicConfig(
    format="%(message)s",
    level=logging.DEBUG,
)

async def main():

    print(f"TEST: Starting tests")
    key = await Key.createKey()
    scp = SCP()
    context = await scp.connect("wss://klave-prod.secretarium.org", key)
    #await debug_list_apps(context)

    # Define AppId
    my_app_id = "master.5ef5aa83.klavemyapp.Idemia.klave.network"

    # Create a new secure element transaction
    print(">> Creating new secure element transaction...")

    tx = context.newTx(
        my_app_id,
        "createSecureElement",
        None,
        {
            "key": "satya",
            "field1": "SE4_field1",
            "field2": "SE4_field2",
            "creationDate": 0,
            "status": "active"
        }
    )

    # Set listeners for transaction results and errors
    tx.onError(lambda message: print(f"Transaction Error: {message}"))
    tx.onResult(lambda message: print(f"Transaction Result: {message}"))

    # Send the transaction
    print(">> Sending transaction...")
    await tx.send()

    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Application interrupted by user.")