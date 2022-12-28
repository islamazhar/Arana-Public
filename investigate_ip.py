#####################################################################3
# Various analysis functions for investigating IPs and usernames.
# Write custom code in main as needed.
# heuristics.py has most of the updated/newest heuristics, but leaving
# this in case it has any other heuristics we need.
#####################################################################
from analysis_queries import create_connection, get_where, school, pers_config
from ipwhois import IPWhois
from pprint import pprint


import time
import os
import ast
import pickle as pickle
import json
import numpy as np
if school == "madison":
    import geoip2.database

db, cursor = create_connection()

def get_whois(ip):
    if school == "madison":
        try:
            return IPWhois(ip).lookup_whois()
        except Exception as e:
            print(e)
            return None
    else:
        return None
    
def get_ISP_name(ip):
    try:
        with geoip2.database.Reader('/data/GeoMaxMind/GeoIP2-ISP.mmdb') as reader:
            response = reader.isp(ip)
        return response.isp
    except Exception as e:
        #print(e)
        return "Exception in get_ISP_name func"
    
def get_successful_usernames_for_ip(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip, result=1)
    query = "SELECT username FROM {}  {};".format(pers_config["table"], where)
    cursor.execute(query)
    usernames = [x[0] for x in cursor.fetchall()]
    return set(usernames), len(usernames)

def get_connecting_ips(ip, threshold_attempts=None, threshold_ratio=None, start=None, end=None):
    where = get_where(start=start, end=end, more=True)
    if threshold_attempts is None and threshold_ratio is None:
        query = "SELECT COUNT(*), ip FROM (SELECT ip FROM sso.measurements {} username IN (SELECT DISTINCT username FROM sso.measurements {} ip = %s)) AS t GROUP BY ip;".format(where, where)
        cursor.execute(query, (ip,))
    else:
        query = "SELECT COUNT(*) AS c, ip, SUM(result) AS s FROM (SELECT ip, result FROM sso.measurements {} username IN (SELECT DISTINCT username FROM sso.measurements {} ip = %s)) AS t GROUP BY ip HAVING c >= %s AND s/c <= %s;".format(where, where)
        cursor.execute(query, (ip, threshold_attempts, threshold_ratio))

    result = cursor.fetchall()
    return result

def get_unique_usernames(ip, start=None, end=None):
    #query = "SELECT DISTINCT username FROM attempts WHERE ip = %s;"
    where = get_where(start=start, end=end, more=True)
    query = "SELECT COUNT(*), username FROM (SELECT username FROM sso.measurements {} ip = %s) AS t GROUP BY username;".format(where)
    cursor.execute(query, (ip,))
    #result = [x[0] for x in cursor.fetchall()]
    result = cursor.fetchall()
    return result

def get_num_unique_usernames(ip, start=None, end=None, result=None):
    where = get_where(start=start, end=end, result=result, ip=ip)
    query = "SELECT COUNT(DISTINCT(username)) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    result = cursor.fetchone()[0]
    return result

def most_common_user_agent(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT user_agent FROM {} {}  GROUP BY user_agent ORDER BY COUNT(*) DESC LIMIT 1;".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def null_user_agents(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT COUNT(*) FROM {} {} AND user_agent IS NULL;".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_unique_user_agents(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT COUNT(DISTINCT(user_agent)) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_successes(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip, result=1)
    query = "SELECT COUNT(*) FROM {} {}".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_successes_in_breach(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip, result=1, pwd_in_breach=1)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_unique_usernames_success(ip, start=None, end=None):
    where = get_where(start=start, end=end, result=1, ip=ip)
    query = "SELECT COUNT(DISTINCT username) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_uniq_valid_users(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = """
            SELECT COUNT(DISTINCT(username)) 
            FROM {} {} AND (result_code  LIKE '%InvalidCredentials%' OR result = 1)
            """.format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_uniq_invalid_users(ip, start=None, end=None):
    all_uniq_users = get_unique_usernames(ip, start=start, end=end)
    total_uniq_users = len(all_uniq_users)
    total_valid_uniq_users = get_num_uniq_valid_users(ip, start=start, end=end)
    total_invalid_uniq_users = total_uniq_users - total_valid_uniq_users
    return total_invalid_uniq_users
     

def get_num_password_in_breach(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip, pwd_in_breach=1)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_strong_password_in_breach(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip, pwd_in_breach=1, zxcvbn=1)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_users_in_breach(ip, start=None, end=None):
    where = get_where(start=start, end=end, username_in_breach=1, ip=ip)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_password_in_hashcat(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT COUNT(*) FROM {} {} AND in_top_5k_hashcat = 1;".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_pair_in_breach(ip, start=None, end=None):
    where = get_where(start=start, end=end, pair_in_breach=1, ip=ip)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]

def get_num_failure_pair_in_breach(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip, pair_in_breach=1, result=0)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where, ip)
    cursor.execute(query)
    return cursor.fetchone()[0]


# Tweaked = (0 < edit_dist <= 3 OR ppsm == 0 OR pass2path rank <= 1000) ) 
# todo: do we need more ganularity? tweaked maked by [ed, ppsm, p2p]?
# todo: add a new colum in attempts table `is_tweaked` to avoid duplicate calculation
def get_num_Tweaked_Passwords_In_Breach(ip, start=None, end=None):
    
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT credential_tweaking_measurements_json FROM {} {}".format(pers_config["table"], where) # todo: use json.
    cursor.execute(query,)
    rows = cursor.fetchall()
    tweaked = 0
    for row in rows:
        #ctm = pickle.loads(row[0])
        ctm = ast.literal_eval(row[0].replace('null', 'None'))
        if len(ctm) > 1:
            exact = False
            tweaked_pw = False
            for p in ctm:
                if (p[0] is not None and p[0] <= 3 and p[0] > 0) or (p[1] is not None and p[1] == 0) or (p[2] is not None and p[2] <= 1000):
                    tweaked_pw = True
                if (p[0] is not None and p[0] == 0):
                    exact = True
                    break
            if exact == False and tweaked_pw == True:
                tweaked +=1    
    return tweaked

def zxcvbn_scores_for_ip(ip, zxcvbn=1, start=None, end=None):
    where = get_where(start=start, end=end, zxcvbn=zxcvbn, ip=ip)
    query =  "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    rows = cursor.fetchone()[0]
    return rows

def get_avg_attempts_per_user(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT username, count(*) from {} {} GROUP BY username".format(pers_config["table"], where)
    cursor.execute(query)
    num_attempts_by_username = []
    for row in cursor:
        num_attempts_by_username.append(row[1])
    return np.mean(np.array(num_attempts_by_username)) 


def get_interarrival_time_stat(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT timestamp FROM {} {}  ORDER BY timestamp ASC;".format(pers_config["table"], where)
    #print(query)
    cursor.execute(query)
    prev = -1
    interarrival_times = []
    for row in cursor:
        if prev == -1:
            prev = row[0]
            continue
        interarrival_times.append((row[0]-prev).total_seconds())
        # since the unit of catching the login time is seconds, the min_interarrival_times can be zero.
        prev = row[0]
    #print(interarrival_times)
    if len(interarrival_times) == 0:
        return -1, -1, prev, prev, -1
    interarrival_times = np.array(interarrival_times)
    #print(interarrival_times)
    return np.median(interarrival_times), np.mean(interarrival_times), np.max(interarrival_times), np.min(interarrival_times), np.std(interarrival_times)


def get_num_attempts_for_ip(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT COUNT(*) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    return cursor.fetchone()[0]


def get_ave_interarrival(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    # same as highest timestamp - lowest timestamp / num entries
    query = "SELECT MAX(timestamp), MIN(timestamp), COUNT(*) FROM {} {}".format(pers_config["table"], where)
    cursor.execute(query)
    row = cursor.fetchone()
    diff = (row[0] - row[1]).total_seconds()
    return diff / row[2], row[0], row[1], row[2]

def get_distance_for_usernames(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT username, DATE(timestamp) FROM {} {} GROUP BY username, DATE(timestamp) HAVING COUNT(*) > 1;".format(pers_config["table"], where)
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []

    where = get_where(start=start, end=end, ip=ip, more=True)
    for row in rows:
        query = "SELECT distance_from_submissions_by_username FROM sso.measurements {} username = %s AND DATE(timestamp) = %s ORDER BY timestamp DESC LIMIT 1;".format(where)
        cursor.execute(query, (row[0], row[1]))
        dist_pkl = cursor.fetchone()[0]
        if dist_pkl is not None:
            dist = pickle.loads(dist_pkl)
        else:
            dist = None
        result.append((row[0], dist))

    return result

def get_last_distance_array_for_ip(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    # for each day this ip was active, get last entry's dist array
    query = "SELECT DISTINCT DATE(timestamp) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    dates = cursor.fetchall()
    distances = []

    for row in dates:
        date = row[0]
        query = "SELECT distance_from_submissions_by_ip FROM {} {} AND DATE(timestamp) = %s ORDER BY timestamp DESC LIMIT 1;".format(pers_config["table"], where)
        cursor.execute(query, (date,))
        dist_pkl = cursor.fetchone()[0]

        if dist_pkl is None:
            distances.append((date, None))
        else:
            dist = pickle.loads(dist_pkl)
            distances.append((date, dist))

    return distances

def get_num_unique_pwds_per_day(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT DISTINCT DATE(timestamp) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    dates = cursor.fetchall()
    unique_pwds = []

    for row in dates:
        date = row[0]
        unique_count = 0
        total = 0
        same_in_a_row = []
        same = 1

        query = "SELECT distance_from_submissions_by_ip FROM sso.measurements {} AND DATE(timestamp) = %s;".format(where)
        cursor.execute(query, (date,))
        entries = cursor.fetchall()
        for entry in entries:
            # TODO: return to this. Decide what to do in this case
            if entry[0] is None: continue

            distance = pickle.loads(entry[0])[:-1]
            if 0 not in distance: unique_count += 1
            if len(distance) > 0 and distance[-1] == 0:
                same += 1
            else:
                same_in_a_row.append(same)
                same = 1
            total += 1

        unique_pwds.append((date, unique_count, total, same_in_a_row))

    return unique_pwds

def assign_pwds_per_day(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = "SELECT DISTINCT DATE(timestamp) FROM {} {};".format(pers_config["table"], where)
    cursor.execute(query)
    dates = cursor.fetchall()
    result = []
    id_ = 0

    for row in dates:
        date = row[0]
        date_passwords = []

        query = "SELECT username, distance_from_submissions_by_ip FROM {} {} AND DATE(timestamp) = %s;".format(pers_config["table"], where)
        cursor.execute(query, (date,))
        entries = cursor.fetchall()
        for entry in entries:
            if entry[1] is None:
                date_passwords.append((entry[0], "unknown"))
                continue

            distance = pickle.loads(entry[1])[:-1]
            i = distance.index(0) if 0 in distance else -1
            if len(distance) == 0 or i == -1 or i >= len(date_passwords):
                pwd = "password{}".format(id_)
                id_ += 1
            else:
                # get index of pwd in date passwords
                #i = distance.index(0)
                pwd = date_passwords[i][1]

            date_passwords.append((entry[0], pwd))

        result.append((date, date_passwords))

    return result

def username_password_ratio_per_day(ip, start=None, end=None):
    print("getting username password ratio per day for ip {}...".format(ip))
    assigned = assign_pwds_per_day(ip, start=start, end=end)
    print("parsing assignments...".format(ip))
    out_file = "case_studies/{}.upratio.txt".format(ip)
    # [(date, [(u1, p1), (u2, p2) ..]] ]
    # for each date:
    # get total # unique pwds and total # unique usernames
    with open(out_file, "w") as f:
        f.write("date,num unique usernames, num unique passwords, unique u:p ratio\n")

        for d, l in assigned:
            usernames = set([ll[0] for ll in l])
            passwords = set([ll[1] for ll in l])
            f.write("{},{},{},{}\n".format(d, len(usernames), len(passwords), len(usernames)/len(passwords)))

# returns [(date, [password1, password2, ...]), ..]
def assign_pwds_per_day_username(username, start=None, end=None):
    where = get_where(start=start, end=end, more=True)
    query = "SELECT DISTINCT DATE(timestamp) FROM {} {} username = %s;".format(pers_config["table"], where)
    cursor.execute(query, (username,))
    dates = cursor.fetchall()
    result = []
    id_ = 0

    for row in dates:
        date = row[0]
        date_passwords = []

        query = "SELECT distance_from_submissions_by_username FROM {} {} username = %s AND DATE(timestamp) = %s;".format(pers_config["table"], where)
        cursor.execute(query, (username, date))
        entries = cursor.fetchall()
        for entry in entries:
            if entry[0] is None:
                date_passwords.append("unknown")
                continue

            distance = pickle.loads(entry[0])[:-1]
            i = distance.index(0) if 0 in distance else -1
            if len(distance) == 0 or i == -1 or i >= len(date_passwords):
                pwd = "password{}".format(id_)
                id_ += 1
            else:
                # get index of pwd in date passwords
                #i = distance.index(0)
                pwd = date_passwords[i]

            date_passwords.append(pwd)

        result.append((date, date_passwords))
    return result

def get_readable_num_in_row(l):
    result = []
    last = -1
    count = 1
    for el in l:
        if el == last:
            count += 1
        else:
            if count > 1:
                result.append("{} x {}".format(count, last))
            else:
                result.append(last)
            count = 1
        last = el
    return result

def short_case_study(ip, start=None, end=None):
    connecting = sorted(get_connecting_ips(ip, start=start, end=end), key=lambda x: x[0], reverse=True)
    unique_usernames = sorted(get_unique_usernames(ip, start=start, end=end), key=lambda x: x[0], reverse=True)
    successes = get_num_successes(ip, start=start, end=end)
    in_breach = get_num_password_in_breach(ip, start=start, end=end)
    ave_interarrival, max_ts, min_ts, total = get_ave_interarrival(ip, start=start, end=end)
    print("     total attempts: {}".format(total))
    print("     num successes: {}".format(successes))
    print("     num in breach: {}".format(in_breach))
    print("     min timestamp: {}".format(min_ts))
    print("     max timestamp: {}".format(max_ts))
    print("     num unique connecting ips: {}".format(len(connecting)))
    print("     num unique usernames: {}".format(len(unique_usernames)))
    print("     ave interarrival: {}".format(ave_interarrival))

def assigned_analysis(assigned):
    # assigned: [(date, [(username, password), ...]), ...]
    # group by passwords, sort by most common
    # group by usernames, sort by most common
    
    password_group = {}
    username_group = {}
    for day in assigned:
        pairs = day[1]

        for pair in pairs:
            if pair[0] in username_group:
                username_group[pair[0]].append(pair[1])
            else:
                username_group[pair[0]] = [pair[1]]

            if pair[1] in password_group:
                password_group[pair[1]].append(pair[0])
            else:
                password_group[pair[1]] = [pair[0]]

    return username_group, password_group

def password_reuse_across_ips(ips, start=None, end=None):
    where = get_where(start=start, end=end, more=True)
    param = ",".join(["'{}'".format(ip) for ip in ips])
    query = "SELECT username, COUNT(*) AS c, d FROM (SELECT username, ip, DATE(timestamp) AS d FROM sso.measurements {} ip in ({}) GROUP BY username, ip, d) AS t GROUP BY username, d HAVING c > 1;".format(where, param)
    cursor.execute(query)
    username_dates = cursor.fetchall()

    # for each username and date for which the username had attempts from multiple ips
    total = 0
    reused = 0
    for username_date in username_dates:
        # get all attempts for the username and date
        query = "SELECT ip, distance_from_submissions_by_username FROM sso.measurements WHERE username = %s AND DATE(timestamp) = %s;"
        cursor.execute(query, (username_date[0], username_date[2]))
        rows = cursor.fetchall()
        ips = []
        pwds = []
        for row in rows:
            dist = pickle.loads(row[1]) if row[1] is not None else None
            if dist is not None:
                if len(dist) != len(ips):
                    print("ERROR: distance is length {}, and ips is length {}".format(len(dist), len(ips)))
                else:
                    for i, el in enumerate(dist):
                        if el == 0 and ips[i] != row[0]: # unique
                            reused += 1
                            break

            total += 1
            ips.append(row[0])

        # if password is unique (no 0's in array) and ip not in previous set

    # what do we want to return here? 
    # num unique usernames/dates for which this is true out of total
    return reused, total

# gets stats and other behavioral information about the input IP
def case_study(ip, start=None, end=None):
    connecting = sorted(get_connecting_ips(ip, start=start, end=end), key=lambda x: x[0], reverse=True)
    unique_usernames = sorted(get_unique_usernames(ip, start=start, end=end), key=lambda x: x[0], reverse=True)
    successes = get_num_successes(ip, start=start, end=end)
    successes_in_b = get_num_successes_in_breach(ip, start=start, end=end)
    unique_success = get_num_unique_usernames_success(ip, start=start, end=end)
    pwd_in_breach = get_num_password_in_breach(ip, start=start, end=end)
    pair_in_breach = get_num_pair_in_breach(ip, start=start, end=end)
    pwd_in_hashcat = get_num_password_in_hashcat(ip, start=start, end=end)
    common_ua = most_common_user_agent(ip, start=start, end=end)
    null_ua = null_user_agents(ip, start=start, end=end)
    distances = get_last_distance_array_for_ip(ip, start=start, end=end)
    unique_pwds = get_num_unique_pwds_per_day(ip, start=start, end=end)
    assigned_pwds = assign_pwds_per_day(ip, start=start, end=end)
    distances_usernames = get_distance_for_usernames(ip, start=start, end=end)
    ave_interarrival, max_ts, min_ts, total = get_ave_interarrival(ip, start=start, end=end)
    whois = json.dumps(get_whois(ip), indent=4)

    with open("case_studies/{}.stats.txt".format(ip), "w") as f:
        f.write("==============================================\n")
        f.write("total attempts: {}\n".format(total))
        f.write("min timestamp: {}\n".format(min_ts))
        f.write("max timestamp: {}\n".format(max_ts))
        f.write("num unique connecting ips: {}\n".format(len(connecting)))
        f.write("num unique usernames: {}\n".format(len(unique_usernames)))
        f.write("num successes: {}\n".format(successes))
        f.write("num successes where pwd in breach: {}\n".format(successes_in_b))
        f.write("num unique usernames with success: {}\n".format(unique_success))
        f.write("num attempts where pwd in breach: {}\n".format(pwd_in_breach))
        f.write("num attempts where pair in breach: {}\n".format(pair_in_breach))
        f.write("num attempts where pwd in hashcat: {}\n".format(pwd_in_hashcat))
        f.write("ave interarrival: {}\n".format(ave_interarrival))
        f.write("most common user agent: {}\n".format(common_ua))
        f.write("num null user agents: {}\n".format(null_ua))
        f.write("==============================================\n")
        f.write("WhoIs Info\n")
        f.write("{}\n".format(whois))
        f.write("==============================================\n")
        f.write("connecting ips\n")
        f.write("{}\n".format(str(connecting)))
        f.write("==============================================\n")
        f.write("unique usernames\n")
        f.write("{}\n".format(str(unique_usernames)))
        #f.write("==============================================\n")
        #f.write("distance from other pwds for same ip\n")
        #f.write("{}\n".format("\n".join([str(d) for d in distances])))
        #f.write("==============================================\n")
        #f.write("unique pwds per day\n")
        #f.write("{}\n".format("\n".join([str((u[0], u[1], u[2], get_readable_num_in_row(u[3]))) for u in unique_pwds])))
        f.write("==============================================\n")
        f.write("assigned pwds per day\n")
        f.write("{}\n".format("\n".join([str(a) for a in assigned_pwds])))
        f.write("==============================================\n")
        f.write("distance from other pwds for this ip per username\n")
        f.write("{}\n".format("\n".join([str(d) for d in distances_usernames])))

# outputs usernames for a given password and (assigned) passwords for a given username into files
# for manual analysis
def case_assigned(ip, start=None, end=None):
    assigned = assign_pwds_per_day(ip, start=start, end=end)
    username_group, password_group = assigned_analysis(assigned)
    #print(len(username_group.keys()))
    #print(len(password_group.keys()))
    pmean = 0
    pmed = 0
    umean = 0
    umed = 0
    puniques = []
    uuniques = []

    with open("case_studies/{}.password.txt".format(ip), "w") as f:
        plist = sorted(list(password_group.items()), key=lambda x: len(x[1]), reverse=True)
        for t in plist:
            unique = len(set(t[1]))
            puniques.append(unique)
            f.write("{} - ({} unique) {}:\n".format(t[0], unique, t[1]))

    with open("case_studies/{}.username.txt".format(ip), "w") as f:
        ulist = sorted(list(username_group.items()), key=lambda x: len(x[1]), reverse=True)
        for t in ulist:
            unique = len(set(t[1]))
            uuniques.append(unique)
            f.write("{} - ({} unique) {}:\n".format(t[0], unique, t[1]))

    with open("case_studies/{}.up_ratio.txt".format(ip), "w") as f:
        f.write("{} mean usernames tried for same password: {}\n".format(ip, np.mean(puniques)))
        f.write("{} median usernames tried for same password: {}\n".format(ip, np.median(puniques)))
        f.write("{} mean passwords tried for same username: {}\n".format(ip, np.mean(uuniques)))
        f.write("{} median passwords tried for same username: {}\n".format(ip, np.median(uuniques)))

# find whether the successes from the input ips were flagged in the PASS db
# this is per campaign, so the input is a list of ips involved in the campaign 
# TODO: we could extend this to also work with the Wisconsin compreds db
def compare_successful_with_compromised(ips, compromised_file="data/pass_1220_0621_encrypted.csv"):
    usernames = set()
    total_successful_attempts = 0
    for ip in ips:
        unique_usernames, total = get_successful_usernames_for_ip(ip)
        usernames.update(unique_usernames)
        total_successful_attempts += total

    compromised = set()
    with open(compromised_file) as f:
        for line in f:
            split = line.strip().split(",")
            compromised.add(split[0])

    intersect = usernames.intersection(compromised)
    print("usernames: {}".format(len(usernames)))
    print("total success: {}".format(total_successful_attempts))
    print("intersect: {}".format(len(intersect)))
    print([u for u in usernames if u not in intersect])
    # return num successful users in compromised db, fraction, total successes
    return len(intersect), len(intersect) / len(usernames), len(usernames), total_successful_attempts

def compare_compromised_case_study_6(compromised_file="data/pass_1220_0621_encrypted.csv"):
    query = "SELECT username, count(*) FROM sso.measurements WHERE result=1 AND timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY username;"
    cursor.execute(query)
    rows = cursor.fetchall()
    username_count = {u:c for u, c in rows}
    usernames = set(map(lambda x: x[0], rows))

    total_successful_attempts = 0
    for row in rows:
        total_successful_attempts += row[1]
    
    compromised = set()
    with open(compromised_file) as f:
        for line in f:
            split = line.strip().split(",")
            compromised.add(split[0])

    intersect = usernames.intersection(compromised)
    print("usernames: {}".format(len(usernames)))
    print("total successul: {}".format(total_successful_attempts))
    print("intersect: {}".format(len(intersect)))
    for i in intersect:
        print("{}: {}".format(i, username_count[i]))
    #print([u for u in usernames if u not in intersect])
    return len(intersect), len(intersect) / len(usernames), len(usernames)

# threshold_ratio: success to failure ratio (only consider ips <= this ratio)
# threshold_attempts: only consider ips with at least this num attempts
def find_connected_component(ip, threshold_ratio=0.1, threshold_attempts=100, seen=None, start=None, end=None):
    # 1) find all connecting ips to this ip
    # 2) filter these ips by the thresholds
    connecting = [row[1] for row in get_connecting_ips(ip, threshold_attempts=threshold_attempts, threshold_ratio=threshold_ratio, start=start, end=end)]
    # 3) return this ip + recurse(sub ip)
    result = set()
    result.add(ip)
    result.update(connecting)

    for ip_ in connecting:
        if seen is not None and ip_ in seen: continue
        subcomponent = find_connected_component(ip_, threshold_ratio, threshold_attempts, seen=result)
        result |= subcomponent

    return result

def get_top_suspicious_ips(N=10, threshold_attempts=100, threshold_ratio=0.1, order_by="count", start=None, end=None):
    where = get_where(start=start, end=end)
    ob = {"count": " c ", "ratio": " fts "}
    #query = "SELECT COUNT(*) AS c, ip, SUM(result) AS s FROM attempts GROUP BY ip HAVING c >= %s AND s/(c-s) <= %s ORDER BY {} DESC LIMIT %s;".format(ob[order_by])
    #query = "SELECT COUNT(*) AS c, ip, SUM(result) AS s, (SUM(result)/(COUNT(*)-SUM(result))) as stf, (COUNT(*)-s)/s as fts FROM attempts GROUP BY ip HAVING c >= %s AND stf <= %s ORDER BY {} DESC LIMIT %s;".format(ob[order_by])
    query = "SELECT ip, c, (s / (c-s)) AS stf, ((c-s) / s) AS fts FROM (SELECT ip, COUNT(*) AS c, SUM(result) AS s FROM sso.measurements {} GROUP BY ip HAVING c >= %s) AS t HAVING stf <= %s ORDER BY {} DESC LIMIT %s;".format(where, ob[order_by])
    cursor.execute(query, (threshold_attempts, threshold_ratio, N))
    rows = cursor.fetchall()
    return rows

def get_top_suspicious_usernames(N=10, threshold_attempts=100, threshold_ratio=0.1, order_by="count", start=None, end=None):
    where = get_where(start=start, end=end)
    ob = {"count": " c ", "ratio": " fts "}
    #query = "SELECT COUNT(*) AS c, username, SUM(result) AS s FROM attempts GROUP BY username HAVING c >= %s AND s/(c-s) <= %s {} DESC LIMIT %s;".format(ob[order_by])
    query = "SELECT username, c, (s / (c-s)) AS stf, ((c-s) / s) AS fts FROM (SELECT username, COUNT(*) AS c, SUM(result) AS s FROM sso.measurements {} GROUP BY username HAVING c >= %s) AS t HAVING stf <= %s ORDER BY {} DESC LIMIT %s;".format(where, ob[order_by])
    cursor.execute(query, (threshold_attempts, threshold_ratio, N))
    rows = cursor.fetchall()
    return rows

def get_interesting_credtweak_measurements_username(username, threshold):
    query = "SELECT credential_tweaking_measurements FROM sso.measurements where username = %s;"
    cursor.execute(query, (username,))
    rows = cursor.fetchall()

    total = 0
    for row in rows:
        ctm = pickle.loads(row[0])
        if len(ctm) > 1:
            for p in ctm:
                if (p[0] is not None and p[0] <= 3) or (p[1] is not None and p[1] == 0) or (p[2] is not None and p[2] == 0):
                    print(ctm)
                    break
            print(ctm)
            total += 1
    print("Total: {}".format(total))

def get_interesting_credtweak_measurements(start=None, end=None, include_exact=False, top_n=10):
    where = get_where(start=start, end=end)
    query = "SELECT username, ip, result, credential_tweaking_measurements FROM sso.measurements {};".format(where)
    cursor.execute(query)
    rows = cursor.fetchall()

    total = 0
    total_successful = 0
    unique_usernames = set()
    successful = set()
    ips_with_fails = {}
    ips_unique_failing_usernames = {}

    for row in rows:
        username = row[0]
        ip = row[1]
        result = row[2]
        ctm = pickle.loads(row[3])
        if len(ctm) > 1:
            for p in ctm:
                if (p[0] is not None and p[0] <= 3) or (p[1] is not None and p[1] == 0) or (p[2] is not None and p[2] < 100):
                    if p[0] == 0 and include_exact is False: continue
                    unique_usernames.add(username)
                    if result:
                        successful.add(username)
                        total_successful += 1
                    else:
                        if ip in ips_with_fails:
                            ips_with_fails[ip] += 1
                        else:
                            ips_with_fails[ip] = 1

                        if ip in ips_unique_failing_usernames:
                            ips_unique_failing_usernames[ip].add(username)
                        else:
                            ips_unique_failing_usernames[ip] = set([username])
                    total += 1
                    break

    ip_list_1 = sorted(ips_with_fails.items(), key=lambda x:x[1], reverse=True)
    ip_list_2 = sorted(ips_unique_failing_usernames.items(), key=lambda x:len(x[1]), reverse=True)
    top_failed_ips_1 = ip_list_1[:5]
    top_failed_ips_2 = ip_list_2[:top_n]
    print("Timeframe: {} to {}".format(start, end))
    print("Total: {}".format(total))
    print("Total successful: {}".format(total_successful))
    print("Total unique usernames: {}".format(len(unique_usernames)))
    print("Total successful unique usernames: {}".format(len(successful)))
    print("Top failed IPs (unique failing usernames):")
    for ip, st in top_failed_ips_2:
        print(" {} ({} usernames flagged): {}".format(ip, len(st), st))
        short_case_study(ip)
    print("Top failed IPs (total failed attempts):")
    for ip, count in top_failed_ips_1:
        print(" {}: {}".format(ip, count))

def check_ctm(ctm):
    if len(ctm) > 1:
        ed = 0
        ppsm = 0
        p2p = 0
        for p in ctm:
            result_string = ""
            if (p[0] is not None and p[0] <= 2):
                ed += 1
            if (p[1] is not None and p[1] == 0):
                ppsm += 1
            if (p[2] is not None and p[2] == 0):
                p2p += 1

        if ed + ppsm + p2p > 0:
            return True, ed, ppsm, p2p
    return False, 0, 0, 0

def ip_matches_credtweak_heuristic_in_timeframe(ip, start=None, end=None, user_agent=None, output=True):
    db, cursor = create_connection()

    query = "SELECT credential_tweaking_measurements FROM sso.measurements WHERE ip = %s AND timestamp > %s AND timestamp < %s;"
    if user_agent is not None:
        query += " AND user_agent = '{}'".format(user_agent)
    cursor.execute(query, (ip, start, end))
    rows = cursor.fetchall()

    result = np.array([0, 0, 0, 0])
    for row in rows:
        ctm = pickle.loads(row[0])
        sub_result = check_ctm(ctm)
        result = result + np.array(sub_result)

    db.close()
    cursor.close()
        
    if output:
        print("# attempts matching heuristic: {}".format(result[0]))
        print("# submitted password-breached password pairs flagged by edit distance: {}".format(result[1]))
        print("# submitted password-breached password pairs flagged by ppsm: {}".format(result[2]))
        print("# submitted password-breached password pairs flagged by pass2path: {}".format(result[3]))
    return result[0], result[1], result[2], result[3]

def ip_matches_unknown_username_in_timeframe(ip, start=None, end=None, user_agent=None, output=False):
    query = "SELECT COUNT(*) FROM sso.measurements WHERE ip = %s AND timestamp > %s AND timestamp < %s AND result_code = -1765328378"
    if user_agent is not None:
        query += " AND user_agent = '{}'".format(user_agent)
    cursor.execute(query, (ip, start, end))
    uu = cursor.fetchone()[0]
    if output:
        print("unknown usernames: {}".format(uu))
    return uu

def ip_in_breach(ip, start=None, end=None, user_agent=None):
    query = "SELECT SUM(appeared_in_breach) FROM sso.measurements WHERE ip = %s AND timestamp > %s AND timestamp < %s"
    if user_agent is not None:
        query += " AND user_agent = '{}'".format(user_agent)
    cursor.execute(query, (ip, start, end))
    sum_ = cursor.fetchone()[0]
    print("Pair in breach : {}".format(sum_))
    return sum_

def get_summary_stats_cs_6():
    query = "SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM sso.measurements WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY ip HAVING c < 50 AND c >= 5 AND s/c < 0.25 AND u/c >= .8;"
    cursor.execute(query)
    rows = cursor.fetchall()
    ips = [r[0] for r in rows]
    ipq = "('{}')".format("','".join(ips))
    print(len(ips))

    q = "SELECT COUNT(DISTINCT username), COUNT(*), SUM(result), SUM(username_appeared_in_breach), SUM(password_appeared_in_breach) FROM sso.measurements WHERE ip IN {} AND timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00'".format(ipq)
    cursor.execute(q)
    return cursor.fetchone()

def get_specific_attack(extra=True):
    #query = "SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, COUNT(DISTINCT username) AS u FROM attempts WHERE timestamp > '2021-04-08' AND timestamp < '2021-04-10' GROUP BY ip HAVING c < 50 AND c > 10 AND s < 5 AND u > 10 AND p > 3;"
    #query = "SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM attempts WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY ip HAVING c < 50 AND c >= 5 AND s < 5 AND u >= 3;"
    #query = "SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(username_appeared_in_breach), SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM sso.measurements WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY ip HAVING c < 50 AND c >= 5 AND s/c < 0.25 AND u/c >= .8;"
    query = "SELECT ip, min(timestamp), max(timestamp), COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(username_appeared_in_breach), SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM sso.measurements WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' GROUP BY ip HAVING c < 50 AND c >= 5 AND s/c < 0.25 AND u/c >= .8;"
    #query = "SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM attempts WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY ip HAVING s < 5;"
    # unknown username result code: -1765328378
    cursor.execute(query)
    rows = cursor.fetchall()
    print("\n".join([str(r) for r in rows]))
    print(len(rows))
    with open("logs/case_study_3.new.csv", "w") as f:
        if extra:
            f.write("ip,mit,total attempts,successes,password in breach,username in breach,pair in breach,unique users,num attempts unknown username,num flagged by credtweak heuristic,credtweak-flagged by edit dist,credtweak-flagged by ppsm,credtweak-flagged by pass2path\n")
        else:
            f.write("ip,total attempts,successes,password in breach,pair in breach,unique users\n")
        for r in rows:
            mit = round((r[2] - r[1]).total_seconds()/r[3], 2)
            if extra:
                ctmh = ip_matches_credtweak_heuristic_in_timeframe(r[0], start="2021-04-09 02:07:00", end="2021-04-09 07:17:00", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36", output=False)
                uu = ip_matches_unknown_username_in_timeframe(r[0], start="2021-04-09 02:07:00", end="2021-04-09 07:17:00", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36")
                f.write("{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(r[0], mit, r[3], r[4], r[5], r[6], r[7], r[8], uu, ctmh[0], ctmh[1], ctmh[2], ctmh[3]))
            else:
                f.write("{},{},{},{},{},{}\n".format(r[0], r[1], r[2], r[3], r[4], r[5]))

# filtered = filter with criteria for case study 6; if False, include all ips in that timerange with the user agent
# include_zero = include edit distance of 0 in the histogram data
def get_histogram_data_cs_6(filtered=True, include_zero=False):
    if filtered:
        query = "SELECT credential_tweaking_measurements FROM sso.measurements WHERE ip IN (\
            SELECT ip FROM (\
                SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM sso.measurements WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY ip HAVING c < 50 AND c >= 5 AND s/c < 0.25 AND u/c >= .8\
            ) AS t\
        );"
    else:
        query = "SELECT credential_tweaking_measurements FROM sso.measurements WHERE ip IN (\
            SELECT ip FROM (\
                SELECT ip, COUNT(*) AS c, SUM(result) AS s, SUM(password_appeared_in_breach) AS p, SUM(appeared_in_breach), COUNT(DISTINCT username) AS u FROM sso.measurements WHERE timestamp > '2021-04-09 02:07:00' AND timestamp < '2021-04-09 07:17:00' AND user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36' GROUP BY ip \
            ) AS t\
        );"
    # unknown username result code: -1765328378
    cursor.execute(query)
    rows = cursor.fetchall()
    result = []

    for r in rows:
        ctm = pickle.loads(r[0])
        if len(ctm) <= 1: continue
        eds = [el[0] for el in ctm[1:] if (include_zero or el[0] != 0) and el[0] is not None]
        if len(eds) == 0: continue
        result.append(min(eds))

    s1 = "filtered" if filtered else "unfiltered"
    s2 = "with_zero" if include_zero else "no_zero"
    with open("logs/histogram.cs_6.{}.{}.csv".format(s1, s2), "w") as f:
        f.write("\n".join([str(r) for r in result]))
    return result

def investigate_username(username):
    query = "SELECT DATE(timestamp), username, distance_from_submissions_by_username, credential_tweaking_measurements FROM sso.measurements WHERE username = %s GROUP BY DATE(timestamp);"

    get_interesting_credtweak_measurements(username, None)

    assigned_per_day = assign_pwds_per_day_username(username, start=None, end=None)
    for tup in assigned_per_day:
        unique = set(tup[1])
        print("Date: {}; {} total passwords; {} unique passwords".format(tup[0], len(tup[1]), len(unique)))

def update_unique_pw_column(start=None, end=None, batch=100000):
   where = get_where(start=start, end=end)
   while True:
       s1 = time.time()
       query = """
               SELECT id, distance_from_submissions_by_ip, timestamp FROM {} {} AND is_unique_pws_by_ip IS NULL ORDER BY timestamp LIMIT {};
               """.format(pers_config["table"], where, batch)        
       cursor.execute(query)
       rows = cursor.fetchall()
       s2 = time.time()
       updated_cols = 0
       for entry in rows:
           attempt_id = entry[0]
           if entry[1] is None:
               is_unique_pws = 1
               #This is a unique password as it the first submission.
           else:
               distance = pickle.loads(entry[1])[:-1]
              
               i = distance.index(0) if 0 in distance else -1
               if len(distance) > 0 and i !=-1 and i <=len(distance):
                   is_unique_pws = 0
                   #This is not a unique password. 
               else:
                   is_unique_pws = 1
          
           updated_cols +=1
           if updated_cols % 10000 == 0:
               print(f'{updated_cols} <--> {time.time() - s1}')       
          
           query = """
                   UPDATE {}
                   SET is_unique_pws_by_ip={}
                   WHERE id={};
                   """.format(pers_config["table"], is_unique_pws, attempt_id)
           cursor.execute(query)
       s3 = time.time()
       print(f'time taken to update  {s3 - s2} seconds')
       if updated_cols == 0:
           # no more updates to be done.
           break
   return "success"

def unique_passwords_for_ip(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    res = []
    query = "SELECT SUM(is_unique_pws_by_ip) FROM {} {}".format(pers_config["table"], where)
    cursor.execute(query)
    res = cursor.fetchone()
    if res is None or res[0] is None:
        return -1 
    return res[0]

def update_unqiue_pw_by_username_column(start=None, end=None, batch=100000):
    where = get_where(start=start, end=end)
    while True:
       s1 = time.time()
       query = """
               SELECT id, distance_from_submissions_by_username, timestamp FROM {} {} ORDER BY timestamp LIMIT {};
               """.format(pers_config["table"], where, batch)        
       cursor.execute(query)
       rows = cursor.fetchall()
       s2 = time.time()
       updated_cols = 0
       for entry in rows:
           attempt_id = entry[0]
           if entry[1] is None:
               is_unique_pws_by_username = 1
               #This is a unique password as it the first submission.
           else:
               distance = pickle.loads(entry[1])[:-1]
              
               i = distance.index(0) if 0 in distance else -1
               if len(distance) > 0 and i !=-1 and i <=len(distance):
                   is_unique_pws_by_username = 0
                   #This is not a unique password. 
               else:
                   is_unique_pws_by_username = 1
          
           updated_cols +=1
           if updated_cols % 10000 == 0:
               print(f'{updated_cols} <--> {time.time() - s1}')       
          
           query = """
                   UPDATE {}
                   SET is_unique_pws_by_username={}
                   WHERE id={};
                   """.format(pers_config["table"], is_unique_pws_by_username, attempt_id)
           cursor.execute(query)
       s3 = time.time()
       print(f'time taken to update  {s3 - s2} seconds')
       if updated_cols == 0:
           # no more updates to be done.
           break
    return "success"

def unique_passwords_for_username(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    res = []
    query = "SELECT SUM(is_unique_pws_by_username) FROM {} {}".format(pers_config["table"], where)
    cursor.execute(query)
    res = cursor.fetchone()
    if res is None or res[0] is None:
        return -1 
    return res[0]

# todo: not sure if the following function is working properly. Needs testing...
def get_avg_uniq_pws_by_username_for_ip(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = """
            SELECT username, timestamp, distance_from_submissions_by_username 
            FROM {} {}
            """.format(pers_config["table"], where)
            
    cursor.execute(query)
    rows = cursor.fetchall()
    #print(rows)
    #print(rows[0:len(rows)][0])
    dict = {}
    for row in rows:
        username = row[0]
        end = row[1]
        distance = pickle.loads(row[2])[:-1] #why are you not using JSON?
        is_unqiue_pws = 1
        look_back = len(distance)
        #print(distance, username, end)
        where = get_where(start=start, end=end, username=username)
        query = """
                    SELECT {} 
                    FROM {} {} 
                    ORDER BY timestamp DESC 
                    LIMIT  {}""".format(pers_config["ip"], pers_config["table"], where, look_back)
        cursor.execute(query)
        for i, another_row in enumerate(cursor):
            another_ip = another_row[0]
            #print(client_ip, end='\t')
            if another_ip == ip:
                if distance[look_back-i-1] == 0:
                    is_unqiue_pws = 0
        #print("\n===================")
        if username not in dict.keys():
            dict[username] = 0
        
        dict[username] += is_unqiue_pws
    
    
    total = 0.0
    for key, val in dict.items():
        total += val 
    print(total, len(dict))
    return total/len(dict)
                
    

def get_result_code_for_ip(ip, start=None, end=None):
    where = get_where(start=start, end=end, ip=ip)
    query = """ 
            SELECT result_code, count(distinct username), COUNT(*) 
            FROM {} {}  
            GROUP BY result_code;
            """.format(pers_config["table"], where)
    #print(query)
    cursor.execute(query)
    rows = cursor.fetchall()
    result = {} #converting result to map 
    for row in rows:
        result[row[0]] = [row[1], row[2]]
    return result


if __name__ == "__main__":
    # IPs to evaluate
    #update_unique_pw_column(start='2021-01-16', end='2021-06-01', batch=100000)

    # Usecase 1: Evaluate a predetermined set of IPs
    ips = list(set([
        "132.236.144.92",
        "67.249.92.118",
        "98.159.219.130",
        "67.80.211.100",
        "68.175.149.62",
        "172.58.203.165",
        "24.59.55.175",
        "172.79.153.35",
        "184.53.48.169",
        "100.16.173.4"
    ]))
    start = "2021-02-14"
    end = "2021-02-28"
    for ip in ips:
        print(ip)
        case_study(ip, start=start, end=end)
        case_assigned(ip, start=start, end=end)

    ## Usecase 2: Find connected component for a specific IP, and evaluate all IPs in that component
    #comp = find_connected_component("40.65.114.116", threshold_ratio=1.0, threshold_attempts=100)
    #for ip in comp:
    #    print(ip)
    #    case_study(ip) #, end="2021-01-28 00:00:00")
    #    case_assigned(ip)

    ## Usecase 3a: Get top suspicious ips based on ratio success to failure and num attempts
    #top = get_top_suspicious_ips(N=20, threshold_attempts=80, threshold_ratio=0.30, order_by="ratio") #1, start="2021-03-01")
    #for row in top:
    #    ip = row[0]
    #    #print("{} : total {}, fail to success: {}, connected comp {}".format(ip, row[1], row[1] - row[2] / row[2], len(find_connected_component(ip))))
    #    print("{} : total {}, fail to success: {}".format(ip, row[1], (row[1] - row[2]) / row[2]))

    ## Usecase 3b: Get top suspicious usernames based on ratio success to failure and num attempts
    #top = get_top_suspicious_usernames(N=10, threshold_attempts=100, threshold_ratio=0.30, order_by="ratio")
    ## username, count, stf, fts
    #for row in top:
    #    username = row[0]
    #    print("{} : total {}, success-to-fail {}".format(username, row[1], row[2]))

    #    #if wanting to mark which things were in a connected component
    #    #print("{} {}: total {}, successes {}, connected comp {}".format(ip, "in first connected comp" if ip in already else "", row[0], row[2], len(find_connected_component(ip))))

    ## Other
    #print(password_reuse_across_ips(ips))
    #print(compare_successful_with_compromised(["50.16.153.186"], compromised_file="data/pass_encrypted.csv"))

    ## Marina 
    #get_interesting_credtweak_measurements(start="2021-02-01", end="2021-03-01", top_n=10)
    #compare_successful_with_compromised(ips, compromised_file="data/pass_encrypted.csv")
    #print(get_summary_stats_cs_6())
#    get_specific_attack()
