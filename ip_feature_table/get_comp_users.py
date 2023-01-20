import json
import sys; sys.path.append("..")

import numpy as np
import pandas as pd
import os 
from libs.analysis_queries import *


query = f""" SELECT distinct(netid) FROM {config.COMP_USER_TABLE}; """
df = pd.read_sql(query, db)
df.to_csv(os.getcwd() + "/../" + config.COMP_USR_FLOC, index=False, compression="bz2")