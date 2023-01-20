import json
import sys; sys.path.append("..")

import numpy as np
from scipy import stats
import re
import matplotlib.pyplot as plt
import math
import os
# import libs.config_anonymize as config
# import libs.config as config


from libs.analysis_queries import *

##################### Setting the threshold for NR and FF ########################################
Ts = {}
columns = ["NR","FF"]
query = """ SELECT {} FROM ip_features where NR > 1 and FF > 0;
            """.format(",".join(col for col in columns))

cursor.execute(query)
rows  = cursor.fetchall()
print("# of <IP, date> pairs fetched is = ", len(rows))


# Ncols = len(columns)
# for i in range(Ncols):
#     Ts[columns[i]] = np.zeros(101)
#     arr = np.array([row[i]  for row in rows])
#     for j in range(1,101):
#         Ts[columns[i]][j] = np.percentile(arr, j)
        

        
# percentile_values = [50, 80, 90, 95]
# for i in range(Ncols):
#     mode = stats.mode(Ts[columns[i]])[0]
#     s = 80
#     direction = 1
#     if columns[i] == "FF": direction =-1 
#     # Go up/down til 80th percentile is eqal to mode.
#     while abs(mode-Ts[columns[i]][s]) < 0.1:
#         s+=direction
#     # print(columns[i], s, Ts[columns[i]][s])


    
# for i in range(1, 101):
#     print(f"{i},{Ts['NR'][i]}")    
    

# plt.plot(range(1,101), Ts["FF"][1:101])
# plt.xlabel("Percentile")
# plt.ylabel("FF")
# print("FF", stats.mode(Ts["FF"]))
# plt.show()

# plt.plot(range(1,101), Ts["NR"][1:101])
# plt.xlabel("Percentile")
# plt.ylabel("NR")
# print("NR", stats.mode(Ts["NR"]))
# plt.show()



# After observing the graph of NR and NU we set the threshold for NR and FF
Ts["FF"] = 0.8
Ts["NR"] = 7



######################## Filtering SCHOOL VPNS ###########################
from ipaddress import ip_address, ip_network


SCHOOL_VPNS = ["72.33.0.0/16", "144.92.0.0/16",  "128.104.0.0/16", "128.105.0.0/16", "146.151.0.0/17", 
              "146.151.128.0/17", "198.133.224.0/24", "198.133.225.0/24", "198.51.254.0/24"]
PATTERNS = ["(.*)university(.*)", "(.*)Wisc(.*)",  "(.*)Institute(.*)", "(.*)of(.*)Technology(.*)",   "(.*)School(.*)", 
            "(.*)Academy(.*)"]

def is_school_vpn(ip, ISP):
    myip = ip_address(ip)
    for school_VPN in SCHOOL_VPNS:
        other_subnet = ip_network(school_VPN)
        if myip in other_subnet:
            return True
    if ISP is None:
        return False
    for pat in PATTERNS:
        res = re.search(pat, ISP, re.IGNORECASE)
        if res is not None:
            return True
    return False

columns = [pers_config["ip"], "DATE", "ISP", "NU", "NR",
           "os_json_cnt", "app_json_cnt", "browser_json_cnt",  "usernames", "successful_usernames", "MIT_Mean", "SIT", 
           "FPIB", "FTP", "FNUA", "NUA", "FF", "FVU", "usernames",
           "zxcvbn_0", "zxcvbn_1", "duo_responses",
           pers_config["auppu"]
           ]
query = """SELECT {} FROM ip_features where NR > {} and FF > {};
            """.format(",".join(col for col in columns), Ts["NR"], Ts["FF"])
            
HFR = pd.read_sql(query, db)
print("Size of HFR = ", len(HFR))
HFR["duo_success"] = [json.loads(x)["success"] for x in HFR["duo_responses"]]


"""1. Filtering based on DUO_completed > 0. Make sure to run the `update_duo_entries.py before
"""

df = HFR.query("duo_success == 0")
N = len(df)
print("Filtering based on DUO completed", len(HFR) - N)

""" 2. Filtering school IP
"""

res = []
for ip, ISP  in zip(df[pers_config["ip"]], df["ISP"]):
    res.append(is_school_vpn(ip, ISP) == False)
df = df[res]

print("Filtered school IP, Date pairs", N  - len(df))
N = len(df)


"""3. Filtering Malformed Client
"""
df = df.query(f"({pers_config['auppu']}*NU)/NR > 0.10")
print("Malformed clients", N  - len(df))
print("All IP, DATE pairs after filtering...", len(df))


"""svaing filtered HFR.
"""
FILTERED_LSETS_LOC = os.getcwd() + "/../" + config.FILTERED_LSETS_LOC
df.to_csv(FILTERED_LSETS_LOC, index=False, compression="bz2") # clustering can be run on these Lsets