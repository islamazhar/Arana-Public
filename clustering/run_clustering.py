import sys
sys.path.append("..")

import ast
import pandas as pd
import numpy as np
import time 
import copy
import matplotlib.pyplot as plt
import os

from sklearn.cluster import AgglomerativeClustering
from kneed import KneeLocator
from ipaddress import IPv4Address


# import libs.config_anonymize as config
import libs.config as config 

from clustering.get_cluster_stat import *


pers_config = config.persistent_db

"""Further preprocessing on HFR
"""
def process_df(HFR):
    HFR['DATE'] = HFR['DATE'].astype('datetime64[ns]')

    cols = ["os_json_cnt", "app_json_cnt", "browser_json_cnt",  "usernames", "successful_usernames"]
    # [fixme:] try json.loads() here...
    for col in cols:
        HFR[col] = [ast.literal_eval(x) for x in HFR[col]]
        if  "usernames" in col:
            HFR[col] = [ set([j   for  jj in sub for j in jj]) for sub in HFR[col]]
    return HFR




######## custom distance func #########################

''' for parallel computation'''
def my_distance_fn_args(args):
    df = args[0]
    i = args[1]
    j = args[2]
    return i, j, my_distance_fn(df.iloc[i], df.iloc[j])

import geoip2.database
def get_subnet_mask(ip):
    # print(ip)
    try:
        with geoip2.database.Reader(os.getcwd() + "/../" + config.GEO_IP_FLOC + '/GeoIP2-ISP.mmdb') as reader:
            response = reader.isp(ip)
        return response.network
    except Exception as e:
        # print(e)
        #if e is FileNotFoundError then send an warning...
        if e is FileNotFoundError or e is PermissionError:
            print("Expection in get_subnet_mask Error is = " + e)
            sys.exit(1)
        return "NA"


def get_IP_distance(point1, point2): #2
    # IP, ISP
    # print(point1["client_ip"], point2["client_ip"])
    if point1["client_ip"] == point2["client_ip"]:
        return 0
    if get_subnet_mask(point1["client_ip"]) == get_subnet_mask(point2["client_ip"]): #hwta if both of them is NA?
        return (1 - np.exp(-1))
    if point1["ISP"] == point2["ISP"]:
        return (1 - np.exp(-2))
    return 1.0

def get_date_distance(point1, point2): #3
    # MIT, SIT, Date
    result = 0.0
    days = abs((point1["DATE"] - point2["DATE"]).days)
    result += (1 - np.exp(-days))
    return result
              
def get_interarrival_time(point1, point2):
    result = 0
    #mit = abs(point1["MIT_Mean"] - point2["MIT_Mean"])/60.00 # per minutes
    result += abs((point1["MIT_Mean"] - point2["MIT_Mean"])/(point1["MIT_Mean"] + point2["MIT_Mean"]))
    #result += (1 - np.exp(-mit))
    
    #sit = abs(point1["SIT"] - point2["SIT"])/60.00
    
    result += abs((point1["SIT"] - point2["SIT"])/(point1["SIT"] + point2["SIT"]))
    #result += (1 - np.exp(-sit))
    result = result/2.00
    assert result <= 1, print(result)
    return result

def get_breach_db_distance(point1, point2): #6
              
    result = 0.0
    # features = ["FPIB", "FSPIB", "FUIB", "FCIB", "FICIB", "FTP"]
    features = ["FPIB", "FTP"]
    for feature in  features:
        x = float(point1[feature])
        y = float(point2[feature])
        if x < 0:
              x = 0
        if y < 0:
              y = 0
        if x+y > 0:  
            val = (x-y)/(x+y) # It does not reach 1. if `-1` handle them seperately.  NR = 1000, NR = 5 val ~=0.9. we can try (x-y)/Max(x,y)
            result += val
    result = result/len(features)
    assert result <= 1.0
    return result


def get_user_agent_distance(point1, point2): #3
    # *_json_cnt, FNUA, NUA
    features1 = ["os_json_cnt", "app_json_cnt", "browser_json_cnt"]
    result = 0.0
    for feature in features1:
        os_json_1 = point1[feature]
        os_json_2 = point2[feature]
        keys = set(os_json_1.keys()).union(set(os_json_2.keys()))
        if len(keys) > 0:
            val = 0
            for key in keys:
                v1 = os_json_1[key] if key in os_json_1.keys() else 0
                v2 = os_json_2[key] if key in os_json_2.keys() else 0
                ne = abs(v2-v1)
                dom = max(v2, v1)
                val += (float(ne)/dom)
            result += val/len(keys)
    
    features2 = ["FNUA", "NUA"]
    for feature in  features2:
        x = float(point1[feature])
        y = float(point2[feature])
        if x+y == 0:
            continue
        val = (x-y)/(x+y) 
        result += abs(val)
    result = result/(len(features1) + len(features2))
    assert result <= 1, print(result)
    return result

def get_result_distance(point1, point2): #2
    # FF, FVU, RCJ?
    features = ["FF", "FVU"] #omitting FIV
    result = 0.0
    for feature in features:
        x = float(point1[feature])
        y = float(point2[feature])
        if x+y == 0:
            continue
        val = (x-y)/(x+y) 
        result += abs(val)
    result = result/len(features)
    assert result <= 1
    return result 


def get_common_usernames(point1, point2, verbose=False):
    result = 0.0
    a = point1["usernames"]
    b = point2["usernames"]
    c = a.intersection(b)
    d = a.union(b)
    if verbose:
        print("C --> ", len(c))
        print("D --> ", len(d))
    result += (1 - len(c)/len(d))
    assert result <= 1, print(result)
    return result          
              
def get_zxcvbn_ratio(point1, point2): #2
    x = float(point1["zxcvbn_0"])/(point1["zxcvbn_0"] + point1["zxcvbn_1"])
    y = float(point2["zxcvbn_0"])/(point2["zxcvbn_0"] + point2["zxcvbn_1"])
    if x + y == 0:
        return 0.0
    val = abs(x-y)/(x+y)
    assert val <= 1
    return val 




def get_volumetric_distance(point1, point2): #2
    result = 0.0
    features = ["NR", "NU"]  
    if config.WITH_PW_FLAG:
        features.append(pers_config["auppu"]) # \fixme column name
    
    for feature in  features:
        x = float(point1[feature])
        y = float(point2[feature])
        val = (x-y)/(x+y) 
        result += abs(val)
    return result
              
''' custom distance function '''
def my_distance_fn(point1, point2):
    
    result = 0.0
    v = 0.5/2.0
    v1 = 0.5/(9.0 if config.WITH_PW_FLAG else 6.0)
    
    result += v*get_IP_distance(point1, point2) 
    result += v*get_date_distance(point1, point2)
    
    if config.WITH_PW_FLAG:
        result += v1*get_breach_db_distance(point1, point2)
        result += v1*get_zxcvbn_ratio(point1, point2)
        
    result += v1*get_result_distance(point1, point2)
    result += v1*get_user_agent_distance(point1, point2)
    result += v1*get_common_usernames(point1, point2)
    result += v1*get_volumetric_distance(point1, point2) # 0 - 3
    result += v1*get_interarrival_time(point1, point2)
    assert result <= 1.0, print(result)
    return result
              

from sklearn import preprocessing
def normalize(x):
    x = np.asarray(x)
    min_max_scaler = preprocessing.MinMaxScaler(axis=0)
    x_scaled = min_max_scaler.fit_transform(x)
    return x_scaled


''' computing the distance matrix'''
def compute_distance_matrix_serial(df):
    s = time.time()
    distance_matrix = np.zeros((len(df), len(df)))
    for i in range(0, len(df)):
        if i % 50 == 0:
            print(f"Done with {i*100.00/len(df):.2f} %")
        for j in range(i+1,len(df)):
            distance = my_distance_fn(df.iloc[i], df.iloc[j]) #check the sanity of the custom distance function.
            distance_matrix[i][j] = distance_matrix[j][i]  = distance
    distance_matrix = normalize(distance_matrix)
    e = time.time()
    print(f"Time taken  {e-s:.2f}")
    return distance_matrix


from multiprocessing import Pool
import multiprocessing


def compute_distance_matrix_parallel(df):
    s = time.time()
    CPU_COUNT = min(40,  multiprocessing.cpu_count()-2)
    print("CPU_COUNT = ", CPU_COUNT)
    global distance_matrix
    distance_matrix = np.zeros((len(df), len(df)), dtype=np.float32)
    results = []
    args=[(df, i,j) for i in range(len(df)) for j in range(i+1, len(df))]
    
    c = 0
    with Pool(CPU_COUNT) as pool:
        results = pool.imap_unordered(my_distance_fn_args, args, chunksize=1000) #async version of imap
        for r in results:
            #print(r)
            x = r[0]
            y = r[1]
            distance = r[2]
            distance_matrix[x][y] = distance_matrix[y][x]  = distance
            c +=1
            if c % 1000000 == 0:
                print(c)
    e = time.time()
    # distance_matrix = normalize(distance_matrix)
    print(f"Time taken =  {e-s:.2f} Len of df pairs= {len(args):,}")

    return distance_matrix


    

""" calculating distance threshold
"""
def calculate_distance_threshold(X):
    
    N = X.shape[0]
    print("N = ", N)
    model = AgglomerativeClustering(n_clusters = None, affinity='precomputed', linkage='average', distance_threshold = 0)
    model.fit(X)
    xx = range(len(X)-1)
    yy = []
    for i in range(1, N):
        yy.append(model.distances_[N-i-1])
    plt.plot(xx, yy)
    plt.xlabel("# of clusters")
    plt.ylabel("Merging threshold")
    plt.show()
    kneedle = KneeLocator(yy, xx, S=1.0, curve="convex", direction="decreasing", interp_method="polynomial")
    return kneedle.knee, kneedle.knee_y


if __name__ == '__main__':
    
    fname = os.getcwd() + "/../" + config.FILTERED_LSETS_LOC
    HFR = pd.read_csv(fname, compression="bz2")
    HFR = process_df(HFR)

    print("Loaded # of HFR <IP,DATE> pairs", len(HFR))
    N = len(HFR)
    
    
    FLOC_SUFFIX =  "_with_pw" if config.WITH_PW_FLAG else "_without_pw"
    """ Computing the distance function. [Warning] it may take sometime to finish...
    """
    data = copy.copy(HFR)
    FLOC = os.getcwd() + "/../" + config.DISTANCE_MATRIX_FLOC + FLOC_SUFFIX
    
    # print(FLOC)
    load = False and os.path.exists(FLOC + ".npz") # Change it to false if want to load from file..

    if load == True:
        print("loading distance matrix")
        distance_matrix = np.load(f"{FLOC}.npz")["arr_0"]
    else:
        print("creating distance matrix")
        distance_matrix = compute_distance_matrix_parallel(data)
        np.savez(f"{FLOC}", distance_matrix)
    
    distance_threshold, _ = calculate_distance_threshold(distance_matrix)
    print("Distance Threshold is = ", distance_threshold)


    # running the clustering
    model = AgglomerativeClustering(n_clusters = None, affinity='precomputed', 
                                    linkage='average', distance_threshold = distance_threshold)
    model.fit(distance_matrix)
    HFR["cluster_id"] = model.labels_ #[TODO:] Assign ranks as well.
    # HFR = HFR.sort_values(by=["cluster_id", "ISP", "DATE"], ascending=False)
    # FNAME = os.getcwd() + "/../" + config.CLUS_RES_FLOC
    # HFR.to_csv(FNAME)


    # FNAME = os.getcwd() + "/../" + config.CLUS_RES_FLOC

    # attacks_df = pd.read_csv(FNAME)
    attack_camp = []
    COLS  =  [ "NR", "NU", "FNUA", "AUPPU", "FUIB", "FCIB", "FPIB", "FTP", "FSPIB",  "ISPs", "DATES_active", "IPs", "zxcvbn_0", "zxcvbn_1", "comp_users", "uniq_comp_users",  "# of Lsets", "FF", "FVU", "cluster_id"]

    for cluster_id in set(HFR["cluster_id"]):
        stats = get_attack_campaign_stats(HFR, cluster_id)
        attack_camp.append(stats)
        
    attack_camp = pd.DataFrame(attack_camp, columns=COLS)
    attack_camp = attack_camp[(attack_camp["NR"] >= 5000) |
                              (attack_camp["NU"] >= 5000) | 
                              (attack_camp["AUPPU"] > 24) 
                              ]
    attack_camp_stats = attack_camp.sort_values(by=["NR"], ascending=False)


    all_features = ["id", "client_ip", "ISP", "is_proxy", #IP info
                "DATE", "MIT_Mean", "MIT_Median", "SIT",  # Time info
                "NR", "NU",  pers_config["auppu"], # Volumetric Info
                "FVU", "FF", "FPIB", "FSPIB", "FUIB", "FCIB", "FICIB", "FTP", "FNUA" , "FIU", #Breach DB info
                "zxcvbn_1", "zxcvbn_0",  #Password strength
                "os_json_cnt", "app_json_cnt", "browser_json_cnt" , "NUA", #User agent info
                "RCJ", "duo_responses", # login and Duo result
                "usernames", "successful_usernames", # usernames
                "cluster_id"
                ]

    fout = os.getcwd() + "/../" + config.RESULTS_FLOC + FLOC_SUFFIX
    writer = pd.ExcelWriter(fout, engine='xlsxwriter')
    HFR[all_features].to_excel(writer, sheet_name="Lsets", startrow=0, index=False)
    attack_camp_stats[COLS].to_excel(writer, sheet_name=f'campaign_stats', startrow=0, index=False)
    writer.close()