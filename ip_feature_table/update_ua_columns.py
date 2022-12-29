import sys; sys.path.append("..")

from libfiles.analysis_queries import *
from libfiles.investigate_ip import *
from libfiles.whois import *

from datetime import *



import pandas as pd
import pickle
import json


db, cursor = create_connection()

query = """SELECT id, IP, date FROM ip_features""" 
d = pd.read_sql(query, db)
column_names = set()

for i, (id, ip, date) in enumerate(zip(d.id, d.IP, d.date)):
    # find all attempts for the <ip, date> pair
    os = {}
    app = {}
    browser = {}
    query = "SELECT user_agent from attempts where client_ip = %s and cast(timestamp as date) = %s"
    res = pd.read_sql(query, db, params = (ip, date,))
    for user_agent in res["user_agent"]:
         if user_agent is None:
            continue
         _os = get_os_name(user_agent)
         if _os not in os.keys():
                os[_os] = 0
         os[_os] +=1
                              
         _app = get_app_name(user_agent)
         if _app not in app.keys():
                app[_app] = 0
         app[_app] +=1
                              
         _browser = get_browser_family_name(user_agent)
         if _browser not in browser.keys():
                browser[_browser] = 0
         browser[_browser] +=1
          
         column_names.add(_browser)
         column_names.add(_os)        
         column_names.add(_app)
         
    ins_query = """UPDATE ip_features set os_json_cnt = %s where id = {}""".format(id)
    cursor.execute(ins_query, (json.dumps(os),))
    ins_query = """UPDATE ip_features set app_json_cnt = %s where id = {}""".format(id)
    cursor.execute(ins_query, (json.dumps(app),))
    ins_query = """UPDATE ip_features set browser_json_cnt = %s where id = {}""".format(id)
    cursor.execute(ins_query, (json.dumps(browser),))
    i +=1 
    if i % 100 == 0:
        print(i)
                   


with open('kos.txt','wb') as f:
   pickle.dump(column_names, f)