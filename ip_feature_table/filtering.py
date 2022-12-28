'''
This will output a CSV file of HFR <IP,DATE> pairs 
'''


Ts = {}
columns = ["NR","FF"]
# basic filter NR > 1 and FF > 0
query = """ SELECT {} FROM ip_features where NR > 1 and FF > 0;
            """.format(",".join(col for col in columns))

cursor.execute(query)
rows  = cursor.fetchall()
print("# of <IP, date> pairs", len(rows))


Ncols = len(columns)
for i in range(Ncols):
    Ts[columns[i]] = np.zeros(101)
    arr = np.array([row[i]  for row in rows])
    for j in range(1,101):
        Ts[columns[i]][j] = np.percentile(arr, j)
        

        
percentile_values = [50, 80, 90, 95]
for i in range(Ncols):
    mode = stats.mode(Ts[columns[i]])[0]
    s = 80
    direction = 1
    if columns[i] == "FF": direction =-1 
    # Go up/down til 80th percentile is eqal to mode.
    while abs(mode-Ts[columns[i]][s]) < 0.1:
        s+=direction
    print(columns[i], s, Ts[columns[i]][s])


    
for i in range(1, 101):
    print(f"{i},{Ts['NR'][i]}")    
    

plt.plot(range(1,101), Ts["FF"][1:101])
plt.xlabel("Percentile")
plt.ylabel("FF")
print("FF", stats.mode(Ts["FF"]))
plt.show()

plt.plot(range(1,101), Ts["NR"][1:101])
plt.xlabel("Percentile")
plt.ylabel("NR")
print("NR", stats.mode(Ts["NR"]))
plt.show()


# plt.plot(range(1,101), Ts["UWR"][1:101])
# plt.xlabel("Percentile")
# plt.ylabel("UWR")
# plt.show()


# Fetching data based on the 80th percentile.
# can you use Kneeplot???
Ts = {}
# Ts["FF"] = 0.8
# Ts["NR"] = 7

Ts["FF"] = 0.5
Ts["NR"] = 3


school_VPNs = ["72.33.0.0/16", "144.92.0.0/16",  "128.104.0.0/16", "128.105.0.0/16", "146.151.0.0/17", 
              "146.151.128.0/17", "198.133.224.0/24", "198.133.225.0/24", "198.51.254.0/24"]


patterns = ["(.*)university(.*)", "(.*)Wisc(.*)",  "(.*)Institute(.*)", "(.*)of(.*)Technology(.*)",   "(.*)School(.*)", 
            "(.*)Academy(.*)"]
from ipaddress import ip_address, ip_network

def is_school_vpn(ip, ISP):
    myip = ip_address(ip)
    for school_VPN in school_VPNs:
        other_subnet = ip_network(school_VPN)
        if myip in other_subnet:
            return True
    if ISP is None:
        return False
    for pat in patterns:
        res = re.search(pat, ISP, re.IGNORECASE)
        if res is not None:
            return True
    return False

def get_usernames_with_success_duo(ip, date):
    success_unames = set()
    query = """SELECT username, duo_id from attempts where client_ip = %s and cast(timestamp as date) = %s;"""
    query2 = """SELECT result from sso.duologs where id={};"""
    df = pd.read_sql(query,  db, params = (ip, date))
    for uname, duo_id in zip(df["username"], df["duo_id"]):
        
        if duo_id is None or math.isnan(duo_id):
            continue
        cursor.execute(query2.format(duo_id))
        for  res in cursor:
            if res[0] == "success":
                success_unames.add(uname)
    return success_unames


# 1. Filtering based on DUO_completed > 0
df = HFR.query("success == 0")
N = len(df)
print("Filtering based on DUO completed", len(HFR) - N )

# 2. Filtering school IP
res = []
for ip, ISP  in zip(df["client_ip"], df["ISP"]):
    res.append(is_school_vpn(ip, ISP) == False)
df = df[res]

print("Filtered school IP, Date pairs",N  - len(df))
N = len(df)


# 3. Filtering Malformed Client..
df = df.query("(AUPPU*NU)/NR > 0.10")
print("Malformed clients", N  - len(df))
print("All IP, DATE pairs after filtering...", len(df))


# svaing HFR.
df.to_csv("Filtered_IP_DATES.csv", index=False)


query = f"SELECT *, json_extract(duo_responses, '$.success') > 0 as success from ip_features where FF > 0.8 and NR > 7;"
HFR = pd.read_sql(query, db)
print(len(HFR))
HFR