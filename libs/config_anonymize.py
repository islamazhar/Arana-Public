import os

school = os.getenv("SCHOOL", default="")
build = os.getenv("BUILD", default="")
password = os.getenv("PASSWORD", default="")

assert bool(school) & bool(build)

persistent_db = dict(
    cornell = dict(
        dev = {
            'user': '',
            'password': password,
            'url': "",
            'port': 12345,
            'db_name': "",
            'table': "",
            'ssl': '',
            'start': '',
            'end': '', 
            'ip': '',
            },
        prod = {
            'user': "",
            'password': password,
            'url': "",
            'port': 12345,
            'db_name': '',
            'table': "",
            'ssl': '',
            'start': '',
            'end': '',
            'ip': '',         
            }
        
    ),

    madison = dict(
        dev = {
            'user': '',
            'password': password,
            'url': "",
            'port': 3306,
            'db_name': '',
            'table': "",
            'ssl': '',
            'start': '',
            'end': '',
            'ip': '',  
        },
        prod = {
            'user': '',
            'password': password,
            'url': "",
            'port': 12345,
            'db_name': '',
            'table': "",
            'ssl': '',
            'start': '',
            'end': '',
            'ip': '',        
        }
    )
)[school][build]

""" some data related herlper functions
"""
DATE_FORMAT = '%Y-%m-%d' # My date formate
MYSQL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f'


""" 
File names saved in data folder.
"""
HFR_LOC = "data/HFR.csv"
FILTERED_LSETS_LOC = "data/Filtered_IP_DATES.csv"
DISTANCE_MATRIX_FLOC = "data/distance_matrix_HFR"
DISTANCE_MATRIX_FLOC = "data/distance_matrix_HFR_without_pw"
COMP_USR_FLOC = "data/comp_creds.csv"
CLUS_RES_FLOC = "data/clustering_results.csv"
GEO_IP_FLOC = "data/GeoMaxMind"
RESULTS_FLOC = "data/Results_wo_pws.xlsx"

"""Table names"""
COMP_USER_TABLE = "sso.compreds"

""" with or withour password based features"""
WITH_PW_FLAG = True
