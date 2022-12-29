import geoip2.database

def get_country_name(ip):
    try:
        with geoip2.database.Reader('/data/GeoMaxMind/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
        return response.country.name
    except Exception as e:
        print(e)
        return "NA"
def get_ISP_name(ip):
    try:
        with geoip2.database.Reader('/data/GeoMaxMind/GeoIP2-ISP.mmdb') as reader:
            response = reader.isp(ip)
        return response.isp
    except Exception as e:
        print(e)
        return "NA"
def get_ASN_name(ip):
    try:
        with geoip2.database.Reader('/data/GeoMaxMind/GeoLite2-ASN.mmdb') as reader:
            response = reader.asn(ip)
        return response.autonomous_system_organization
    except Exception as e:
        print(e)
        return "NA"
def get_city_name(ip):
    try:
        with geoip2.database.Reader('/data/GeoMaxMind/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
        return response.city.name
    except Exception as e:
        print(e)
        return "NA"

def get_all(ip):
    print(get_country_name(ip))
    print(get_ISP_name(ip))
    print(get_ASN_name(ip))
    print(get_city_name(ip))

#get_all("3.87.190.104")
#get_all("71.206.171.238")
#get_all("108.169.200.95")
#get_all("212.102.45.93")

from user_agents import parse

def get_os_name(ua_string):
    try:
        user_agent = parse(ua_string)
        return user_agent.os.family
    except Exception as e:
        return "NA"
    
    
def get_app_name():
    pass

def get_browser_family_name():
    pass 
    
