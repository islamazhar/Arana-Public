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

# some data related herlper functions...
DATE_FORMAT = '%Y-%m-%d' # My date formate
MYSQL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f'
HFR_LOC = "data/HFR.csv"
FILTERED_LSETS_LOC = "data/Filtered_IP_DATES.csv"
DISTANCE_MATRIX_FLOC = "data/distance_matrix_HFR"
