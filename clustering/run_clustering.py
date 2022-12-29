import sys; sys.path.append("..")

import ast
import libfiles.config_anonymize as config



fname = config.FILTERED_LSETS_LOC
HFR = pd.read_csv(fname)
HFR['DATE'] = HFR['DATE'].astype('datetime64[ns]')


"""Further preprocessing on SAorHFR"""
cols = ["os_json_cnt", "app_json_cnt", "browser_json_cnt",  "usernames", "successful_usernames"]

for col in cols:
    HFR[col] = [ast.literal_eval(x) for x in HFR[col]]
    if  "usernames" in col:
        HFR[col] = [ set([j   for  jj in sub for j in jj]) for sub in HFR[col]]
#HFR[cols]
print("Loaded # of HFR <IP,DATE> pairs", len(HFR))

