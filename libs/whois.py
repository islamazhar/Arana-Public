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


from user_agents import parse

def get_os_name(ua_string):
    try:
        user_agent = parse(ua_string)
        return user_agent.os.family
    except Exception as e:
        return "NA"
    
    
def get_app_name(ua_string):
    try:
        user_agent = parse(ua_string)
        if user_agent.is_pc:
            return 'desktop'
        if user_agent.is_mobile:
            return 'mobileweb' 
        else:
            return 'unknown'
    except Exception as e:
        return "None"

def get_browser_family_name(ua_string):
    try:
        user_agent = parse(ua_string)
        return user_agent.browser.family if user_agent.browser.family is not None else user_agent.browser.family
    except Exception as e:
        return "None"
    
def get_browser_version(ua_string):
    
    try:
        user_agent = parse(ua_string)
        return user_agent.browser.version if user_agent.browser.version is not None else user_agent.browser.version
    except Exception as e:
        return "None"
    
