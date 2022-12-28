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
            'ssl': '',
            'start': '',
            'end': '', 
            },
        prod = {
            'user': "",
            'password': password,
            'url': "",
            'port': 12345,
            'db_name': '',
            'ssl': '',
            'start': '',
            'end': '',         
            }
        
    ),

    madison = dict(
        dev = {
            'user': '',
            'password': password,
            'url': "",
            'port': 3306,
            'db_name': 'analysis',
            'ssl': '',
            'start': '2020-12-20',
            'end': '2021-03-10',  
        },
        prod = {
            'user': '',
            'password': password,
            'url': "",
            'port': 12345,
            'db_name': '',
            'ssl': '',
            'start': '',
            'end': '',        
        }
    )
)[school][build]


