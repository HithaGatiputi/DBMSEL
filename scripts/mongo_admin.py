"""MongoDB helper used by services.sh.
  init      : create root + app users (first time, via the localhost exception)
  shutdown  : stop the server (mongod --shutdown is Linux-only)
Credentials come from the environment (scripts/_secrets.sh)."""
import os
import sys

import pymongo
from pymongo.errors import AutoReconnect, OperationFailure, ServerSelectionTimeoutError

PORT = int(os.environ.get("MONGOPORT", "27018"))
ROOT_PW, APP_PW = os.environ["MONGO_ROOT_PASSWORD"], os.environ["MONGO_APP_PASSWORD"]


def client(auth: bool):
    kw = dict(serverSelectionTimeoutMS=3000)
    if auth:
        kw.update(username="dbmsel_root", password=ROOT_PW, authSource="admin")
    return pymongo.MongoClient(f"mongodb://127.0.0.1:{PORT}", **kw)


def init():
    try:
        client(True).admin.command("ping")
        print("mongodb users already configured")
        return
    except OperationFailure:
        pass
    c = client(False)   # localhost exception: allowed only while no users exist
    c.admin.command("createUser", "dbmsel_root", pwd=ROOT_PW, roles=["root"])
    a = client(True)
    a["dbmsel_raw"].command("createUser", "dbmsel_app", pwd=APP_PW, roles=[{"role": "readWrite", "db": "dbmsel_raw"}])
    print("mongodb users created (dbmsel_root, dbmsel_app)")


def shutdown():
    for auth in (True, False):
        try:
            client(auth).admin.command("shutdown")
        except (AutoReconnect, ServerSelectionTimeoutError):
            print("mongodb stopped")
            return
        except OperationFailure:
            continue


if __name__ == "__main__":
    {"init": init, "shutdown": shutdown}[sys.argv[1]]()
