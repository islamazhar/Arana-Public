import pandas as pd
# import libs.config_anonymize as config
import libs.config as config
import os

""" getting stats of the clusters """
cols = ["NR", "NU", "FNUA", "AUPPU", "FUIB", "FCIB", "FPIB", "FTP", "FSPIB", "# ISP",  "DATES_active", "# IPS", "zxcvbn_0","zxcvbn_1", "comp_users", "flagged_comp_users", "total_pairs", "FF", "FVU", "y"] # Average Acitivity duration per day?
# id,client_ip,ISP,DATE,MIT_Mean,MIT_Median,SIT,NR,NU,NP,NUA,FVU,FF,FPIB,FSPIB,FUIB,FCIB,FICIB,FTP,FNUA,UWR,RCJ,zxcvbn_1,zxcvbn_0,comments,IR,AUPPU,FIU,os_json_cnt,app_json_cnt,browser_json_cnt,consec_days,duo_responses,is_malicious,comp_users,is_proxy,uniq_comp_users,usernames,cluster_id

# save flagged users
FNAME = os.getcwd() + "/../" + config.COMP_USR_FLOC
flagged_users_df = pd.read_csv(FNAME, compression="bz2")


def get_common_flagged_users(comp_users):
    flagged_users = set([x for x in flagged_users_df["netid"]]) # TODO: "only" consider those subs which are after the IP DATE pair
    return flagged_users.intersection(comp_users)
    
    
def get_compromised_users(data):
    comp_users = []
    for _comp_users in data["successful_usernames"]:
        comp_users.extend(_comp_users)
        
    return set(comp_users)
    

def breach_db_stat(data):
    cols = ["FPIB", "FTP",  "FUIB", "FCIB", "FICIB"]
    results = {}
    for col in cols:
        res = (data["NR"]*data[col]).sum() / data["NR"].sum()
        results[col] = res
    
    FSPIB = 0
    for _FSPIB, nr in zip(data["FSPIB"], data["NR"]):
        FSPIB += 0 if _FSPIB == -1 else _FSPIB*nr
        
    results["FSPIB"] = FSPIB/data["NR"].sum()
    return results

def get_total_usernames(data):
    usernames = []
    for username in data["usernames"]:
        usernames.extend(username)
    return len(set(usernames))



def get_attack_campaign_stats(df, y):
    data = df[df["y"] == y]
    
    NR = data["NR"].sum()
    NU = get_total_usernames(data)
    IPs = len(set(data["client_ip"]))
    ISPs =  len(set(data["ISP"]))
    DATES_active = len(set(data["DATE"]))
    zxcvbn_0, zxcvbn_1 = data["zxcvbn_0"].sum(), data["zxcvbn_1"].sum()
    results = breach_db_stat(data)
    FPIB,  FTP, FSPIB, FUIB, FCIB, FICIB = results["FPIB"], results["FTP"], results["FSPIB"], results["FUIB"], results["FCIB"], results["FICIB"]
    
    FF,  FVU = data["FF"].mean(),  data["FVU"].mean()
    
    AUPPU = (data["AUPPU"]*data["NU"]).sum()/data["NU"].sum()
    FNUA = (data["FNUA"]*data["NR"]).sum()/data["NR"].sum()

    
    NU_mean, NR_mean = data["NR"].mean(), data["NU"].mean()
    # characterizing the campaign
#     CS = (FPIB > Ts["FPIB"] or FCIB > Ts["FCIB"] or FTP > Ts["FTP"] or FUIB > Ts["FUIB"]) and  NU_mean >= Ts["NU"] and NR_mean >= Ts["NR"]
#     PS = (UWR  == 1) and NU_mean >= Ts["NU"] and NR_mean >= Ts["NR"] #TODO: This heuritics seems to be wrong. Add FSPIB, zxcvbn_0??
    compromised_users = get_compromised_users(data)
    flagged_comp_users  = get_common_flagged_users(compromised_users)
    return NR, NU, FNUA, AUPPU, FUIB, FCIB, FPIB, FTP, FSPIB,  ISPs, DATES_active, IPs, zxcvbn_0, zxcvbn_1, len(compromised_users), len(flagged_comp_users),  len(data), FF, FVU, y


