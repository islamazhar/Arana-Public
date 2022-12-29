import sys
sys.path.append("..")

import datetime

from libfiles.investigate_ip import *
from libfiles.analysis_queries import *
import datetime
import pandas as pd
import json

#2021-01-05 10:03:59

start = "2021-01-05"
end = "2021-03-03"

# Doing the reverse trying to connect DUOlogs with attempts.
query = """SELECT id, username, from_unixtime(timestamp) timestamp, result from sso.duologs where 
            cast(from_unixtime(timestamp) as DATE) >= %s and
            cast(from_unixtime(timestamp) as DATE) <= %s and id > 5982436"""

df = pd.read_sql(query, db, params=(start, end,))
print(df.head())  
print("size of df", len(df))
values = []
ins_q = """insert into DUO (duo_id, attempt_ids, username, date, result) values (%s, %s, %s, %s, %s)"""
cnt = 0
for i, (duo_id, uname, time, result) in enumerate(zip(df["id"], df["username"], df["timestamp"], df["result"])):
    
    tim = time +  timedelta(hours=6)
    start = tim - timedelta(minutes=2)
    end = tim + timedelta(minutes=2)

    where = get_where(username=uname, start=start, end=end, result=1)
    query = """SELECT id from attempts {}""".format(where)
    res = pd.read_sql(query, db)
    if len(res) > 0:
        attempt_ids = json.dumps([x for x in res["id"]])
        cnt +=1
    else:
        attempt_ids = None
    values.append((duo_id, attempt_ids, uname, time, result))
    if len(values)  % 1000 == 0:
            cursor.executemany(ins_q, values)
            db.commit()
            print(f"{i}. Row inserted: {cursor.rowcount}")
            value = []
            print(i, cnt)
            
                                       
if len(values) > 0:
        cursor.executemany(ins_q, values)
        db.commit()
        print(f"Last Row inserted: {cursor.rowcount}")
        value = []