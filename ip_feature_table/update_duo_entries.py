import sys
sys.path.append("..")


from libfiles.analysis_queries import *
from libfiles.investigate_ip import *
#from heuristics import *
from datetime import *
from way import *

import time
import sys
import ast
import pandas as pd
import pickle
import json


db, cursor = create_connection()

query2 = "SELECT id, IP, DATE from ip_features" 
ip_features = pd.read_sql(query2, db)


query = """SELECT date, result, attempt_ids FROM DUO"""
cursor.execute(query)

#d = pd.read_sql(query, db)
#column_names = set()


values = {}
# what happens when someone don't click the push? see the duo_log help documentation.
print("Running main loop")
for i, row in enumerate(cursor):
    DATE, result, attempt_ids = row[0], row[1], row[2]
    # todo: may be attempt_ids is json.
    attempt_ids =json.loads(attempt_ids)
    for attempt_id in attempt_ids:
        # get the IP
        #query = "SELECT IP from attempts where id = {}".format(attempt_id)
        #cursor.execute(query)
        #IP = cursor.fetchone()[0]
      
        key = attempt_id + "-" + DATE # aftet than extrac the IP from attempt ID
        if key not in values.keys() and IP in ip_features["IP"] and DATE in ip_features["DATE"]:
            values[key] = {"success": 0, "denied":0, "fraud":0}
        
        values[key][resul] += 1
        break
    break
        
codes = ["success", "denied", "fraud"]
success = []
denied = []
fraud = []

"""
for key, value in values.items():
    ip, date = key.split("-")
    success.append((value["success"], ip, date))
    denied.append((value["denied"], ip, date))
    fraud.append((value["fraud"], ip, date))

ins_query = "UPDATE ip_features set {} = %s where IP=%s and DATE = %s"
for code in codes:
    cursor.executemany(ins_q.format(code), values)
"""