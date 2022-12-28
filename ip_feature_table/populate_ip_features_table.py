import sys; sys.path.append("..")

from analysis_queries import *
from investigate_ip import *
import config


db, cursor = create_connection()
school = os.getenv("SCHOOL")
assert(school is not None)

def get_ips(start=None, end=None):
    where = get_where(start=start, end=end)    
    query = """
            SELECT client_ip, COUNT(id) as c, SUM(result) as k
            FROM {} {} 
            GROUP BY {}
            HAVING c >= 2 AND c > k""".format(TABLE_NAME, where, IP_TYPE) 
            # at least one failed attempts and at least 2 attempts
    
    cursor.execute(query)
    ips = set([row[0] for row in cursor])
    return ips

def get_values(ip, start=None, end=None):
        results = {}
        results["NR"] = get_num_attempts_for_ip(ip, start=start, end=end)
        results["FF"] = 1 - get_num_successes(ip, start=start, end=end)/results["NR"]
        
        results["NU"] = get_num_unique_usernames(ip, start=start, end=end) 
        results["FVU"] = get_num_uniq_valid_users(ip, start=start, end=end)/results["NU"] 
        

        # uniq_username, uniq_password, uw_ratio
        results["NP"] = unique_passwords_for_ip(ip,start=start, end=end) 
         
        if results["NP"] is None or results["NP"] < 1:
            uw_ratio = -1
        else:
            uw_ratio = results["NU"]/results["NP"]
        
        results["UWR"] = uw_ratio

        # interarrival_time
        median, mean, max_t, min_t, sd_interarrival_time  = get_interarrival_time_stat(ip,start=start, end=end)
        
        results["MIT"] = mean

        # user_agent
        results["NUA"] = null_user_agents(ip,start=start, end=end) 
        results["FUA"] =  get_num_unique_user_agents(ip, start=start, end=end) / results["NR"]
        


        # result_codes
        result_code_dict = get_result_code_for_ip(ip,start=start, end=end)
        if school == 'madison':
            result_code_names = ['AccountError', 'InvalidCredentials', 'UnknownUsername', 'Success']
        else:
            result_code_names = [] #todo: add cornel specific result code here...
        
        for result_code_name in result_code_names:
            if result_code_name not in result_code_dict.keys():
                    result_code_dict[result_code_name]  = [0, 0]

        results["RCJ"] = json.dumps(result_code_dict)
        # cred_stuffing
        results["FPIB"] = get_num_password_in_breach(ip, start=start, end=end)/results["NR"] 
        results["FUIB"] = get_num_users_in_breach(ip, start=start, end=end)/results["NR"]
        results["FCIB"] = get_num_pair_in_breach(ip, start=start, end=end)/results["NR"]
        results["FICIB"] =  get_num_failure_pair_in_breach(ip, start=start, end=end)/results["NR"]
        results["FSPIB"] = get_num_strong_password_in_breach(ip, start=start, end=end)/results["NR"]

        # cred_tweaking
        results["FTP"] =  get_num_Tweaked_Passwords_In_Breach(ip, start=start, end=end)/results["NR"]


           
        results["zxcvbn_score_1"] = zxcvbn_scores_for_ip(ip,start=start, end=end, zxcvbn=1)
        results["zxcvbn_score_0"] = zxcvbn_scores_for_ip(ip,start=start, end=end, zxcvbn=0)
        results["AAPU"] = get_avg_attempts_per_user(ip,start=start,end=end)
        results["ISP"] = get_ISP_name(ip)
   
        return results
        
#password_reuse_accors_ip // for the same username?
# todo: add it as a cron job which will run periodically after 1 day and send email if they is any attack.
def insert_row(ips):
    for i, ip in enumerate(ips):
        num_success = get_num_successes(ip, start=start, end=end) 
        num_attempts = get_num_attempts_for_ip(ip, start=start, end=end) 


        num_uniq_valid_users = get_num_uniq_valid_users(ip, start=start, end=end) 
        

        # uniq_username, uniq_password, uw_ratio
        num_uniq_password = unique_passwords_for_ip(ip,start=start, end=end) 
        num_uniq_username = get_num_unique_usernames(ip, start=start, end=end) 
        if num_uniq_password is None or num_uniq_password < 1:
            uw_ratio = -1
        else:
            uw_ratio = num_uniq_username/num_uniq_password


        # interarrival_time
        median, mean, max_t, min_t, sd_interarrival_time  = get_interarrival_time_stat(ip,start=start, end=end)


        # user_agent
        null_ua = null_user_agents(ip,start=start, end=end) 
        num_of_unique_user_agents_submitted =  get_num_unique_user_agents(ip, start=start, end=end) 
        


        # result_codes
        result_code_dict = get_result_code_for_ip(ip,start=start, end=end)
        if school == 'madison':
            result_code_names = ['AccountError', 'InvalidCredentials', 'UnknownUsername', 'Success']
        else:
            result_code_names = [] #todo: add cornel specific result code here...
        
        for result_code_name in result_code_names:
            if result_code_name not in result_code_dict.keys():
                    result_code_dict[result_code_name]  = [0, 0]

        # cred_stuffing
        breach_pws = get_num_password_in_breach(ip, start=start, end=end) 
        breach_users = get_num_users_in_breach(ip, start=start, end=end)
        breach_uw_pair = get_num_pair_in_breach(ip, start=start, end=end)
        incorrect_credentials_uwpair_In_Breach =  get_num_failure_pair_in_breach(ip, start=start, end=end)
        num_of_strong_passwords_in_breach = get_num_strong_password_in_breach(ip, start=start, end=end)

        # cred_tweaking
        num_Tweaked_Passwords_In_Breach =  get_num_Tweaked_Passwords_In_Breach(ip, start=start, end=end) # okay


           
        zxcvbn_score_1 = zxcvbn_scores_for_ip(ip,start=start, end=end, zxcvbn=1)
        zxcvbn_score_0 = zxcvbn_scores_for_ip(ip,start=start, end=end, zxcvbn=0)
        avg_attempts_per_user = get_avg_attempts_per_user(ip,start=start,end=end)

        isp = get_ISP_name(ip)
        
        query = """INSERT INTO ip_features (
                    IP,
                    ISP,
                    DATE, 
                    MIT_Mean, 
                    MIT_Median,
                    SIT, 
                    NR, 
                    NU, 
                    NP,
                    NUA, 
                    FVU,
                    FF, 
                    FPIB, 
                    FSPIB, 
                    FUIB, 
                    FCIB,
                    FICIB, 
                    FTP,
                    FNUA, 
                    AAU,
                    UWR,
                    RCJ,
                    zxcvbn_1,
                    zxcvbn_0,
                    comments, 
                    IR) 
                    VALUES ({});""".format(','.join( '%s' for _ in range(26)))
        try:
                cursor.execute(query, (ip, 
                                       isp,
                                       start, 
                                       mean, 
                                       median, 
                                       sd_interarrival_time, 
                                       num_attempts, 
                                       num_uniq_username, 
                                       num_uniq_password,
                                       num_of_unique_user_agents_submitted , 
                                       num_uniq_valid_users/num_uniq_username,
                                       1.0 - num_success/num_attempts, 
                                       breach_pws/num_attempts,
                                       -1 if breach_pws == 0 else num_of_strong_passwords_in_breach/breach_pws, #[fixme]: Ask Rahul that it should be divied by `breach_pws`
                                       breach_users/num_attempts, 
                                       breach_uw_pair/num_attempts,
                                       incorrect_credentials_uwpair_In_Breach/num_attempts, 
                                       num_Tweaked_Passwords_In_Breach/num_attempts,
                                       null_ua/num_attempts, 
                                       avg_attempts_per_user,
                                       uw_ratio,
                                       json.dumps(result_code_dict),
                                       zxcvbn_score_1,
                                       zxcvbn_score_0,
                                       "No comments",
                                       0,
                                      ))
        except Exception as e:
                print("Error in inserting rows: {}".format(str(e)))
        #break

if __name__ == '__main__':
    today = "2020-12-20"

    while today != "2021-01-25":
        start = format_date(today)
        end = increase_date_by_one_day(today)
        ips = get_ips(start=start, end=end)
        insert_row(ips)
        today = datetime.strptime(end,MYSQL_DATE_FORMAT).strftime(DATE_FORMAT)   
        print(today, len(ips))
