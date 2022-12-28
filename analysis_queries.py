import mysql.connector
import sys 
import pandas as pd
import os
import config
import time as t
import pickle
import datetime
import decimal
from sys import exit

from datetime import *

school = os.getenv("SCHOOL")
assert(school is not None)

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
pers_config = config.persistent_db
print("Connecting to {}@{}".format(pers_config["user"], pers_config["url"]))
def create_connection():
    connected = False
    i = 0 
    while not connected:
        print(pers_config["url"])
        print(pers_config["user"])
        print(pers_config["password"])
        print(pers_config["db"])
        try:
            db = mysql.connector.connect(
                host = pers_config["url"],
                user = pers_config["user"],
                password = pers_config["password"],
                database = pers_config["db"],
                autocommit = True
            )   
            cursor = db.cursor(buffered=True)
            connected = True
        except Exception as e:
            if i >= 15: 
                print("Could not connect to database. Exiting now.")
                print(str(e))
                exit(0)
            t.sleep(1)
            i += 1
    return db, cursor

def close_connection():
    db.close()
    cursor.close()

db, cursor = create_connection()
print("Ready")

def get_where_session(start=None, end=None, automated=None):
    ands = []
    if start is not None:
        ands.append(" timestamp_start >= '{}' ".format(start))
    if end is not None:
        ands.append(" timestamp_end < '{}' ".format(end))
    if automated is not None:
        #ands.append(" automated_score = {} ".format(automated))
        ands.append(" average_interarrival_time < 2 AND num_attempts > 2 ".format(automated))
    where = "WHERE " + " AND ".join(ands) if len(ands) > 0 else ""
    return where
    
def get_where(username=None, result=None, pwd_in_breach=None, username_in_breach=None, pair_in_breach=None, ip=None, hashcat=None, rockyou=None, zxcvbn=None, malformed_password=None, start=None, end=None, more=None):
    ands = []
    if username != None:
        ands.append(" username='{}' ".format(username))
    if result != None:
        ands.append(" result={} ".format(result))
    if pwd_in_breach != None:
        ands.append(" password_appeared_in_breach={} ".format(pwd_in_breach))
    if username_in_breach != None:
        ands.append(" username_appeared_in_breach={} ".format(username_in_breach))
    if pair_in_breach != None:
        ands.append(" appeared_in_breach={} ".format(pair_in_breach))
    if ip != None:
        ands.append(" {} = '{}' ".format(pers_config['ip'], ip))
    if hashcat != None:
        ands.append(" in_top_5k_hashcat={} ".format(hashcat))
    if rockyou != None:
        ands.append(" in_top_5k_rockyou={} ".format(rockyou))
    if zxcvbn != None:
        ands.append(" zxcvbn_score={} ".format(zxcvbn))
    if malformed_password != None:
        ands.append(" malformed_password={} ".format(malformed_password))
    if start != None:
        ands.append(" timestamp >= '{}' ".format(start))
    if end != None:
        ands.append(" timestamp < '{}' ".format(end))
    
        
    ands.append(" timestamp > '2020-11-26 00:00:00' ")

    if more:
        return "WHERE " + " AND ".join(ands) + " AND " if len(ands) > 0 else " WHERE "
    else:
        return "WHERE " + " AND ".join(ands) if len(ands) > 0 else ""

# some data related herlper functions...
DATE_FORMAT = '%Y-%m-%d' # My date formate
MYSQL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f' 
    
def format_date(date_input): #Must be in DATE_FORMAT
    datetimeobject = datetime.strptime(date_input,DATE_FORMAT)
    return datetimeobject.strftime(MYSQL_DATE_FORMAT) #MYSQL format of date.

def increase_date_by_one_day(date_input, days = 1):
    datetimeobject = datetime.strptime(date_input,DATE_FORMAT) + timedelta(days=days)
    return datetimeobject.strftime(MYSQL_DATE_FORMAT)


def get_attempt_statistics(start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT COUNT(*), SUM(result), SUM(appeared_in_breach), SUM(username_appeared_in_breach), SUM(password_appeared_in_breach), SUM(frequently_submitted_password_today), SUM(frequently_submitted_username_today), SUM(zxcvbn_score), SUM(in_top_5k_hashcat), SUM(in_top_5k_rockyou), SUM(in_top_10_passwords), SUM(in_top_100_passwords), SUM(in_top_1000_passwords), SUM(in_top_2k_hashcat), SUM(in_top_2k_rockyou) FROM {} {};".format(pers_config['table'], where)
    start, end = get_start_end(start=start, end=end)
    timedelta = decimal.Decimal((end - start).total_seconds() / (24 * 60 * 60)) # decimal days
    labels = [l.strip() + " per day" for l in "ave count, num successes, num appeared in breach, num username appeared in breach, num password appeared in breach, num frequently submitted password today, num frequently submitted username today, num zxcvbn score = 1, num in top 5k hashcat, num in top 5k rockyou, num in top 10 pwds, num in top 100 pwds, num in top 1k pwds, num in top 2k hashcat, num in top 2k rockyou, average interarrival time by username, average interarrival time by ip, average interarrival time by username-ip".split(",")]
    cursor.execute(query)
    stats = cursor.fetchone()

    interarrivals = []
    ia_where = where + " AND interarrival_time_by_username >= 0 AND interarrival_time_by_username < 300 " if len(where) > 0 else " WHERE interarrival_time_by_username >= 0 AND interarrival_time_by_username < 300 "
    query = "SELECT AVG(interarrival_time_by_username) FROM {} {};".format(pers_config['table'], ia_where)
    cursor.execute(query)
    result = cursor.fetchone()
    interarrivals.append(result[0])

    ia_where = where + " AND interarrival_time_by_ip >= 0 AND interarrival_time_by_ip < 300 " if len(where) > 0 else " WHERE interarrival_time_by_ip >= 0 AND interarrival_time_by_ip < 300 "
    query = "SELECT AVG(interarrival_time_by_ip) FROM {} {};".format(pers_config['table'], ia_where)
    cursor.execute(query)
    result = cursor.fetchone()
    interarrivals.append(result[0])

    ia_where = where + " AND interarrival_time_by_username_ip >= 0 AND interarrival_time_by_username_ip < 300 " if len(where) > 0 else " WHERE interarrival_time_by_username_ip >= 0 AND interarrival_time_by_username_ip < 300 "
    query = "SELECT AVG(interarrival_time_by_username_ip) FROM {} {};".format({}, ia_where)
    cursor.execute(query)
    result = cursor.fetchone()
    interarrivals.append(result[0])

    # convert all stats to be per day
    result = [round(x / timedelta, 2) for x in list(stats) + interarrivals]

    return result, labels

def get_average_attempts_per_user_per_day(start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT AVG(t.count) AS avg FROM ( SELECT COUNT(*) AS count, DATE(timestamp) AS ts, username FROM {} " + where + " GROUP BY username, ts) AS t".format(pers_config['table'])
    cursor.execute(query)
    result = cursor.fetchone()
    return result[0]

def get_99th_attempts_per_user_per_day(start=None, end=None):
    where = get_where(start=start, end=end)
    query = "SELECT COUNT(*) FROM (SELECT username, DATE(timestamp) AS ts FROM {} {} GROUP BY username, ts) AS t;".format(pers_config['table'], where)
    cursor.execute(query)
    count = cursor.fetchone()[0]
    n = int((count - 1) * (1 - 0.99))

    query = "SELECT count FROM (SELECT COUNT(*) AS count, DATE(timestamp) AS ts FROM {} {} GROUP BY username, ts) AS t ORDER BY count DESC LIMIT {}, 1;".format(pers_config['table'], where, n)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_99th_percentile(field, table, start=None, end=None):
    where = "WHERE {} >= 0 AND {} < 300 ".format(field, field) if "interarrival" in field else "WHERE "

    if where != "WHERE ":
        if start != None:
            where += " AND timestamp >= '{}' ".format(start) if ("attempts" in table or "measurements" in table) else " AND timestamp_start >= '{}' ".format(start)
        if end != None:
            where += " AND timestamp < '{}' ".format(end) if ("attempts" in table or "measurements" in table) else " AND timestamp_end < '{}' ".format(end)
    else:
        if start != None:
            where += "timestamp >= '{}' ".format(start) if ("attempts" in table or "measurments" in table) else "timestamp_start >= '{}' ".format(start)
        if end != None:
            where += "timestamp < '{}' ".format(end) if ("attempts" in table or "measurements" in table) else "timestamp_end < '{}' ".format(end)

    query = "SELECT COUNT(*) FROM {} {};".format(table, where if len(where.strip()) > 5 else "")
    cursor.execute(query)
    count = cursor.fetchone()[0]
    n = int((count - 1) * (1 - 0.99))

    query = "SELECT {} FROM {} {} ORDER BY {} DESC LIMIT {}, 1;".format(field, table, where if len(where.strip()) > 5 else "", field, n)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_start_end(start=None, end=None):
    if start is None or end is None:
        new_start, new_end = get_start_end_timestamps(cursor)
    start = new_start if start is None else start
    end = new_end if end is None else end
    return start, end

def get_username_session_statistics(start=None, end=None):
    where = get_where_session(start=start, end=end)
    start, end = get_start_end(start=start, end=end)
    timedelta = decimal.Decimal((end - start).total_seconds() / (24 * 60 * 60)) # decimal days
    query = "SELECT COUNT(*), AVG(num_attempts), AVG(num_unique_ips), AVG(num_unique_user_agents), AVG(num_unique_devices), SUM(ended_with_success), AVG(num_attempts_username_in_breach), AVG(num_attempts_password_in_breach), AVG(num_attempts_password_in_hashcat), AVG(num_attempts_password_in_rockyou), AVG(num_attempts_zxcvbn_score_0), AVG(average_zxcvbn_score) FROM username_sessions {};".format(where)
    labels = "ave count per day, average num attempts, average num unique ips, average num unique user agents, average num unique devices, num ended with success, average num attempts with username in breach, average num attempts with password in breach, average num attempts password in hashcat, average num attempts password in rockyou, average num attempts zxcvbn score 0, average zxcvbn score, average average interarrival time, average min interarrival time".split(",")
    cursor.execute(query)
    result = list(cursor.fetchone())
    result[0] = round(result[0] / timedelta, 2)
    return result, labels

def get_ip_session_statistics(start=None, end=None):
    where = get_where_session(start=start, end=end)
    start, end = get_start_end(start=start, end=end)
    timedelta = decimal.Decimal((end - start).total_seconds() / (24 * 60 * 60)) # decimal days
    query = "SELECT COUNT(*), AVG(num_attempts), AVG(num_unique_usernames), AVG(num_unique_user_agents), AVG(num_unique_devices), SUM(ended_with_success), AVG(num_attempts_username_in_breach), AVG(num_attempts_password_in_breach), AVG(num_attempts_password_in_hashcat), AVG(num_attempts_password_in_rockyou), AVG(num_attempts_zxcvbn_score_0), AVG(average_zxcvbn_score) FROM ip_sessions {};".format(where)
    labels = "ave count per day, average num attempts, average num unique usernames, average num unique user agents, average num unique devices, num ended with success, average num attempts with username in breach, average num attempts with password in breach, average num attempts password in hashcat, average num attempts password in rockyou, average num attempts zxcvbn score 0, average zxcvbn score, average average interarrival time, average min interarrival time".split(",")
    cursor.execute(query)
    result = list(cursor.fetchone())
    result[0] = round(result[0] / timedelta, 2)
    return result, labels

def get_username_ip_session_statistics(start=None, end=None):
    where = get_where_session(start=start, end=end)
    start, end = get_start_end(start=start, end=end)
    timedelta = decimal.Decimal((end - start).total_seconds() / (24 * 60 * 60)) # decimal days
    query = "SELECT COUNT(*), AVG(num_attempts), AVG(num_unique_user_agents), AVG(num_unique_devices), SUM(ended_with_success), AVG(num_attempts_username_in_breach), AVG(num_attempts_password_in_breach), AVG(num_attempts_password_in_hashcat), AVG(num_attempts_password_in_rockyou), AVG(num_attempts_zxcvbn_score_0), AVG(average_zxcvbn_score) FROM username_ip_sessions {};".format(where)
    labels = "count, average num attempts, average num unique user agents, average num unique devices, num ended with success, average num attempts with username in breach, average num attempts with password in breach, average num attempts password in hashcat, average num attempts password in rockyou, average num attempts zxcvbn score 0, average zxcvbn score, average average interarrival time, average min interarrival time".split(",")
    cursor.execute(query)
    result = list(cursor.fetchone())
    result[0] = round(result[0] / timedelta, 2)
    return result, labels

session_type = {1: "username", 2: "ip", 3: "username_ip"}
def get_ia_times(by_username=True):
    field = "username" if by_username else "ip"
    query = "SELECT interarrival_time_by_{} FROM {} ;".format(field, pers_config['table'])
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_ave_ia_times(by_username=True):
    field = "username" if by_username else "ip"
    query = "SELECT average_interarrival_time FROM {}_sessions;".format(field)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_num_attempts_per_session(st=1, automated=None, start=None, end=None):
    field = session_type[st] 
    where = get_where_session(start=start, end=end, automated=automated)
    query = "SELECT num_attempts FROM {}_sessions {};".format(field, where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_ips_per_username_session(start=None, end=None, automated=None):
    where = get_where_session(start=start, end=end, automated=automated)
    query = "SELECT num_unique_ips FROM username_sessions {};".format(where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_ips_per_24_hours(start=None, end=None):
    where = get_where(start=start, end=end)
    query = "SELECT COUNT(DISTINCT ip), timestamp AS ts FROM {} {} GROUP BY username, DATE(ts);".format(pers_config['table'], where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_ip_useragent_pairs_24_hours(start=None, end=None):
    where = get_where(start=start, end=end)
    query = "SELECT COUNT(*) AS c FROM {} {} GROUP BY ip, user_agent, username, DATE(timestamp);".format(pers_config['table'], where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_ip_useragent_pairs_all_time(start=None, end=None):
    where = get_where(start=start, end=end)
    query = "SELECT COUNT(*) AS c FROM {} {} GROUP BY ip, user_agent, username;".format(pers_config['table'], where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_usernames_per_ip_session(start=None, end=None, automated=None):
    where = get_where_session(start=start, end=end, automated=automated)
    query = "SELECT num_unique_usernames FROM ip_sessions {};".format(where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_user_agents_per_session(st=1, start=None, end=None, automated=None):
    field = session_type[st] 
    where = get_where_session(start=start, end=end, automated=automated)
    query = "SELECT num_unique_user_agents FROM {}_sessions {};".format(field, where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_unique_devices_per_session(st=1, start=None, end=None, automated=None):
    field = session_type[st] 
    where = get_where_session(start=start, end=end, automated=automated)
    query = "SELECT num_unique_devices FROM {}_sessions {};".format(field, where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_ratio_usernames_to_attempts(start=None, end=None, automated=None):
    where = get_where_session(start=start, end=end, automated=automated)
    query = "SELECT num_unique_usernames / num_attempts FROM ip_sessions {} AND num_attempts > 1;".format(where)
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def get_credtweak_measurement_dist(type_=1, start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT id, credential_tweaking_measurements, username FROM {} {};".format(pers_config['table'], where)
    cursor.execute(query)
    result = []
    num_attempts = 0
    unique_users = set()

    for i, row in enumerate(cursor):
        ctm = pickle.loads(row[1])
        already_row = False

        for j, el in enumerate(ctm):
            if j == 0: continue # skip valid password
            if (el[type_-1] is not None):
                result.append(el[type_-1])

                if not already_row:
                    num_attempts += 1
                    unique_users.add(row[2])
                    already_row = True

    print("num attempts: {}".format(num_attempts))
    print("num unique users: {}".format(len(unique_users)))

    return result

def get_cred_tweak_from_actual_dist(type_=1, start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT credential_tweaking_measurements, username FROM {} {} credential_tweaking_measurements IS NOT NULL;".format(pers_config['table'], where  + " AND " if len(where) > 1 else " WHERE ")
    print(query)
    cursor.execute(query)
    result = []
    unique_users = set()

    for i, row in enumerate(cursor):
        ctm = pickle.loads(row[0])
        if len(ctm) == 0: continue

        if ctm[0][type_-1] is not None and ctm[0][type_-1] != 0:
            unique_users.add(row[1])

        result.append((row[1], ctm[0][type_-1]))

    print ("Password Reset Users:", len(unique_users))

    return result

#def get_users_w_success_in_dist(type_=1, start=None, end=None, result=None):
#    where = get_where(start=start, end=end, result=result)
#    query = "SELECT id, credential_tweaking_measurements, username FROM attempts {} credential_tweaking_measurements IS NOT NULL;".format(where  + " AND " if len(where) > 1 else " WHERE ")
#    cursor.execute(query)
#    result = []
#
#    for i, row in enumerate(cursor):
#        ctm = pickle.loads(row[1])
#        if len(ctm) < 2: continue
#
#        for j, el in enumerate(ctm):
#            if j == 0: continue
#            if el[type_-1] is not None:
#                result.append(
#        result.append((row[2], ctm[0][type_-1]))
#
#    return result

def get_num_credtweaks_in_session(type_=1, st=1, start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT DISTINCT {}_session_id FROM {} {};".format(session_type[st], pers_config['table'], where)
    cursor.execute(query)
    sids = cursor.fetchall()
    result = []

    for i, sid_row in enumerate(sids):
        #if i % 10000 == 0: print("{} rows processed".format(i))
        sid = sid_row[0]
        query = "SELECT id, credential_tweaking_measurements, username FROM {} {} AND {}_session_id={};".format(pers_config['table'], where, session_type[st], sid)
        cursor.execute(query)
        rows = cursor.fetchall()

        num_this_session = 0
        for row in rows:
            ctm = pickle.loads(row[1])
            already_row = False

            for j, el in enumerate(ctm):
                if j == 0: continue # skip valid password
                if el[type_-1] is not None:
                    if (type_ == 1 and el[type_-1] <= 3) or (type_ == 2 and el[type_ - 1] <= 1):
                        num_this_session += 1

        result.append(num_this_session)
        num_this_session = 0

    return result

def get_unique_pwds_per_user_per_day_dist(start=None, end=None, result=None):
    # for each day, get all unique users
        # for each unique user, get all attempts
            # for each attempt, see if any 0s in array
    where = get_where(start=start, end=end, result=result)
    query = "SELECT t1.id, t1.distance_from_submissions_by_username FROM {} t1 JOIN \
            (SELECT MAX(id) id FROM {} {} GROUP BY username, DATE(timestamp)) AS t2 \
            ON t1.id = t2.id;".format(pers_config['table'], pers_config['table'], where)
    cursor.execute(query)
    counts = []
    for row in cursor:
        dfs = pickle.loads(row[1]) if row[1] is not None else None
        if dfs is None: continue
        counts.append(len(set(dfs)) + 1)

    return counts
    
def automated():
    return "num_attempts > 2 AND average_interarrival_time < 2"

def find_non_standard_user_agents(cursor, start=None, end=None):
    where = get_where(start=start, end=end)
    query = "SELECT id, user_agent FROM {} {} user_agent NOT LIKE '%Mozilla%';".format(pers_config['table'], where + " AND "if len(where) > 0 else "WHERE")
    cursor.execute(query)
    return cursor.fetchall()

def find_credential_stuffing_attempts(cursor, start=None, end=None):
    where = get_where(start=start, end=end)
    query = "SELECT id, username, ip FROM {} {} (appeared_in_breach = 1 OR password_appeared_in_breach = 1);".format(pers_config['table'], where + " AND "if len(where) > 0 else "WHERE")
    cursor.execute(query)
    return cursor.fetchall()

def find_credential_tweaking_attempts(start=None, end=None, result=None, intervals=pd.Timedelta(days=1)):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT id, credential_tweaking_measurements, username FROM {} {};".format(pers_config['table'], where)
    print(query)
    cursor.execute(query)
    cta = []
    count_ed = 0
    count_ppsm = 0
    unique_users = set()
    for i, row in enumerate(cursor):
        ctm = pickle.loads(row[1])
        if len(ctm) > 1:
            for j, m in enumerate(ctm):
                if j == 0: continue # skip valid password
                #if (m[0] is not None and m[0] > 0) and (m[2] is not None and m[2]<1000):
                if m[0] is not None and ((m[0] <= 3) or (m[1] <= 1)):
                #if (m[2] is not None and m[2]<1000):
                # TODO: Add ORs for ppsm and pass2path
                    cta.append(row[0])
                    unique_users.add(row[2])
                    break
                    #if m[0] <= 3:
                    #    count_ed += 1
                    #else:
                    #    count_ppsm += 1
        #if i % 100000 == 0: print("Processed {} rows".format(i))

    #print("PPSM found: {}".format(count_ppsm))
    #print("ED found: {}".format(count_ed))
    print(len(unique_users))
    return cta

def find_password_spraying_sessions_2(cursor, start=None, end=None):
    where = get_where_session(start=start, end=end)
    query = "SELECT id, ip, timestamp_start, timestamp_end FROM ip_sessions {} num_unique_usernames >= 5 AND num_unique_user_agents = 1;".format(where + " AND " if len(where) > 0 else "WHERE")
    cursor.execute(query)
    return cursor.fetchall()

def find_recently_breached_username_password_pairs(cursor, start=None, end=None):
    query = "SELECT c, username, ts FROM (SELECT COUNT(DISTINCT ip) AS c, username, timestamp as ts FROM {} GROUP BY username, DATE(ts)) AS t WHERE c > 2;".format(pers_config['table'])
    # for each username and timestamp, get distance_from_submissions for that day (the last one), and see if there are multiple of the same password (lots of 7s, lots of 0s, etc)
    cursor.execute(query)
    rows = cursor.fetchall()

    for row in rows:
        query = "SELECT distance_from_submissions_by_username FROM {} WHERE username = %s AND DATE(timestamp) = DATE(%s) ORDER BY timestamp DESC LIMIT 1;".format(pers_config['table'])
        cursor.execute(query, (row[1], row[2]))
        result = cursor.fetchone()
        if result is None: continue
        dfs = pickle.loads(result[0])
        counts = [(el, dfs.count(el)) for el in dfs]
        for element in dfs:
            if dfs.count(element) > 2:
                pass

# Flag a username logging in multiple times a day from different (> 4) IP address-user agent pairs
# Result: username-date pairs
def find_recently_breached_usernames(cursor, start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result)
    query = "SELECT username, DATE(timestamp) AS d, COUNT(*) AS c FROM {} {} GROUP BY ip, user_agent, username, d HAVING c > 4;".format(pers_config['table'], where)
    cursor.execute(query)
    return cursor.fetchall()

def find_general_targeted_attack(cursor, start=None, end=None):
    where = get_where(start=start, end=end)
    # Flag a username-date pair if >= 5 (more than a legitimate user is likely to attempt) different passwords tried within 24 hour window
    # For every username-date pair,
        # Iterate through attempts for the username, finding number of "0"s in d_f_s_b_u
    query1 = "SELECT username, DATE(timestamp) AS d, COUNT(*) AS c FROM {} {} GROUP BY username, d HAVING c >= 5;".format(pers_config['table'], where)
    cursor.execute(query1)
    username_dates = cursor.fetchall()
    result = []
    print("Fetched username-date pairs: {}".format(len(username_dates)))

    for i, row in enumerate(username_dates):
        #if i % 10000 == 0 and i != 0: print("Processed {} rows".format(i))
        query2 = "SELECT distance_from_submissions_by_username FROM {} WHERE username = %s AND DATE(timestamp) = %s;".format(pers_config['table'])
        cursor.execute(query2, (row[0], row[1]))
        attempts = cursor.fetchall()
        unique_pwds = 0

        for attempt in attempts:
            dfs = pickle.loads(attempt[0])
            if len(dfs) == 0 or 0 in dfs:
                unique_pwds += 1
        if unique_pwds >= 5:
            result.append((row[0], row[1]))

    return result

def get_edit_distance_from_actual_password(start=None, end=None, result_=None):
    where = get_where(start=start, end=end, result=result_)

    # get all username, datas from attempts
    query = "SELECT username, DATE(timestamp) AS d FROM {} {} GROUP BY username, d;".format(pers_config['table'], where)
    print(query)
    cursor.execute(query)
    username_dates = cursor.fetchall()
    print("Fetched username-date pairs: {}".format(len(username_dates)))

    typo_requests = 0
    results = []

    for i, row in enumerate(username_dates):
        query2 = "SELECT distance_from_submissions_by_username FROM {} WHERE username = %s AND DATE(timestamp) = %s AND result=1 ORDER BY timestamp DESC limit 1;".format(pers_config['table'])
        cursor.execute(query2, (row[0], row[1]))
        result = cursor.fetchone()
        if result is None: continue

        dfs = pickle.loads(result[0])

        typo_requests += dfs.count(1)
        typo_requests += dfs.count(2)

        for element in dfs:
            # correct password
            if element == 0:
                continue

            # incorrect edit distances
            results.append(element)

    print("Total Requests that had Typos: ", typo_requests)
    return results


def store_attack_mapping(cursor, attack_id, attempt_id=None, username=None, date=None, username_session_id=None, ip_session_id=None, username_ip_session_id=None):
    query = "INSERT INTO attack_mappings (attack_id, attempt_id, username, date, username_session_id, ip_session_id, username_ip_session_id) VALUES (%s, %s, %s, %s, %s, %s, %s);"
    try:
        cursor.execute(query, (attack_id, attempt_id, username, date, username_session_id, ip_session_id, username_ip_session_id))
    except Exception as e:
        print("Error: {}".format(str(e)))

def get_start_end_timestamps(cursor):
    query1 = "SELECT timestamp FROM {} ORDER BY timestamp LIMIT 1;".format(pers_config['table'])
    cursor.execute(query1)
    start = cursor.fetchone()[0]

    query2 = "SELECT timestamp FROM {} ORDER BY timestamp DESC LIMIT 1;".format(pers_config['table'])
    cursor.execute(query2)
    end = cursor.fetchone()[0]
    return start, end

def get_attacks_matching(cursor, attack_id, start=None, end=None):
    print(attack_id)
    if attack_id in [1, 2, 7]:
        where = get_where(start=start, end=end)
        query = "SELECT attack_mappings.attempt_id FROM attack_mappings LEFT JOIN {} ON attack_mappings.attempt_id = attempts.id {} attack_mappings.attack_id = {};".format(pers_config['table'], where + " AND " if len(where) > 0 else "WHERE", attack_id)
    elif attack_id in [4]:
        where = get_where_session(start=start, end=end)
        query = "SELECT attack_mappings.ip_session_id FROM attack_mappings LEFT JOIN ip_sessions ON attack_mappings.ip_session_id = ip_sessions.id {} attack_mappings.attack_id = {};".format(where + " AND " if len(where) > 0 else "WHERE", attack_id)
    elif attack_id in [5, 6]:
        where = get_where(start=start, end=end)
        query = "SELECT username, date FROM attack_mappings WHERE attack_id = {};".format(attack_id)
        cursor.execute(query)
        rows = cursor.fetchall()
        param = ",".join(["('{}','{}')".format(r[0], r[1]) for r in rows])
        query = "SELECT id FROM {} {} (username, DATE(timestamp)) IN ({});".format(pers_config['table'], where + " AND " if len(where) > 0 else "WHERE", param)
    cursor.execute(query)
    rows = cursor.fetchall()
    return [x[0] for x in rows]

def get_cred_stuffing_score():
    query = "SELECT username, SUM(result) as s, SUM(password_appeared_in_breach) AS b, COUNT(*) AS c FROM {} GROUP BY username HAVING b >= 1 AND s >= 1 AND (c - b) >= 1;".format(pers_config['table'])
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []
    counts = {}

def get_top_failing_usernames(n):
    query = "SELECT username, count(*) AS C FROM {} WHERE result = 0 GROUP BY username, result ORDER BY C DESC Limit %d;".format(pers_config['table'])
    cursor.execute(query, (n,))
    return cursor.fetchall()

def get_result_code_for_user(username):
    result_types = {"Success": 0, "UnknownUsername": 0, "InvalidCredentials": 0, "AccountError": 0}
    query = "SELECT result_code, count(*) FROM {} WHERE username = %s GROUP BY result_code;".format(pers_config['table'])
    cursor.execute(query, (username,))
    for row in cursor.fetchall():
        result_type = row[0]
        result_count = row[1]

        result_types[result_type] = result_count

    return result_types

def get_all_unsuccessful_ips_for_user(username):
    query = "SELECT COUNT(DISTINCT {}) FROM {} WHERE username = %s AND result = 0;".format(pers_config['ip'], pers_config['table'])
    cursor.execute(query, (username,))
    return cursor.fetchone()

def get_pwds_tried_per_day_for_user(username):
    query = "SELECT DISTINCT DATE(timestamp) FROM {} WHERE username = %s;".format(pers_config['table'])
    cursor.execute(query, (username,))
    dates = cursor.fetchall()
    result = []
    id_ = 0

    for row in dates:
        date = row[0]
        date_passwords = []

        query = "SELECT distance_from_submissions_by_username FROM {} WHERE username = %s AND DATE(timestamp) = %s ORDER BY timestamp ASC;".format(pers_config['table'])
        cursor.execute(query, (username, date))
        entries = cursor.fetchall()
        for entry in entries:

            distance_pickle = entry[0]

            # First attempt of the day for that username
            if distance_pickle is None:
                date_passwords.append("unknown")
                continue

            distance = pickle.loads(distance_pickle)[:-1]
            i = distance.index(0) if 0 in distance else -1
            if len(distance) == 0 or i == -1 or i >= len(date_passwords):
                # new password tried
                pwd = "password{}".format(id_)
                id_ += 1
            else:
                # old password tried
                pwd = date_passwords[i]

            date_passwords.append(pwd)

        result.append((date, date_passwords))

    return result

def get_pwds_tried_per_day_for_ip(ip):
    where = get_where()
    query = "SELECT DISTINCT DATE(timestamp) FROM {} {} AND {} = %s;".format(pers_config['table'], pers_config['ip'], where)

    cursor.execute(query, (ip,))
    dates = cursor.fetchall()
    result = []
    id_ = 0

    for row in dates:
        date = row[0]
        date_passwords = []

        query = "SELECT distance_from_submissions_by_ip FROM {} WHERE {} = %s AND DATE(timestamp) = %s ORDER BY timestamp ASC;".format(pers_config['table'], pers_config['ip'])
        cursor.execute(query, (ip, date))
        entries = cursor.fetchall()
        for entry in entries:

            distance_pickle = entry[0]

            # First attempt of the day for that username
            if distance_pickle is None:
                date_passwords.append("unknown")
                continue

            distance = pickle.loads(distance_pickle)[:-1]
            print(distance)
            i = distance.index(0) if 0 in distance else -1
            if len(distance) == 0 or i == -1 or i >= len(date_passwords):
                # new password tried
                pwd = "password{}".format(id_)
                id_ += 1
            else:
                # old password tried
                pwd = date_passwords[i]

            date_passwords.append(pwd)

        result.append((date, date_passwords))

    return result

def get_dist_pwds_tried_per_day_for_ip(ip):
    days = get_pwds_tried_per_day_for_ip(ip)

    unique_pwds = []
    for day in days:
        unique_pwds.append(len(set(day[1])))
    return unique_pwds

def get_dist_pwds_tried_per_day_for_user(username):
    days = get_pwds_tried_per_day_for_user(username)

    unique_pwds = []
    for day in days:
        unique_pwds.append(len(set(day[1])))
    return unique_pwds

DATE_FORMAT = '%Y-%m-%d' # My date formate
MYSQL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

def increase_date_by_one_day(date_input, days = 1):
    datetimeobject = datetime.strptime(date_input,DATE_FORMAT) + timedelta(days=days)
    return datetimeobject.strftime(MYSQL_DATE_FORMAT)

if __name__ == "__main__":
    #gta = find_general_targeted_attack()
    #print(gta)
    #print(len(gta))
#    cta = find_credential_tweaking_attempts(start="2021-01-16", end="2021-02-01", result=1)
    print(len(find_recently_breached_usernames(start="2021-01-16 00:00:00", end=None, result=None)))
    #print(cta)
    #print(len(cta))

    for row in rows:
        username = row[0]
        s = row[1]
        b = row[2]
        c = row[3]

        query = "SELECT COUNT(*) FROM {} WHERE username = %s AND result = 1 AND password_appeared_in_breach = 1;".format(pers_config['table'])
        cursor.execute(query, (username,))
        pwd_breached = cursor.fetchone()[0] > 0

        query = "SELECT username, ip, result, password_appeared_in_breach, user_agent FROM {} WHERE username = %s;".format(pers_config['table'])
        print(username, flush=True)
        cursor.execute(query, (username,))
        u_rows = cursor.fetchall()

        ips_successful = set()
        uas_successful = set()
        for attempt in u_rows:
            score = 0
            if attempt[3] == 1 and attempt[1] not in ips_successful:
                score += 2

            if attempt[3] == 1 and attempt[4] is None:
                score += 2
            elif attempt[3] == 1 and attempt[4] not in uas_successful:
                score += 1

            if attempt[2] == 1:
                ips_successful.add(attempt[1])
                uas_successful.add(attempt[4])

            if attempt[3] != 1: continue

            if not pwd_breached:
                score += 2

            result.append((username, score))
            if score in counts:
                counts[score] += 1
            else:
                counts[score] = 1

    for key in counts:
        print("{}: {}".format(key, counts[key]))

#if __name__ == "__main__":
#    get_cred_stuffing_score()
