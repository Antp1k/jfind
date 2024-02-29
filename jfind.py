#!/usr/bin/python3

import requests
import argparse
import re
import random
import concurrent.futures
from termcolor import colored as clr

### PARSER
p = argparse.ArgumentParser()
p.add_argument(
        '-l',
        '--list',
        dest="list",
        required=True,
        help="List of target domains."
        )
p.add_argument(
        '-v',
        '--verbose',
        dest="verb",
        action="store_true",
        help="Print error messages, if they occur."
        )
args = p.parse_args()

### USER AGENTS
user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246", "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36", "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.6; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Linux i686; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34", "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34", "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"]

### FUNCTIONS
def user_agent_generator():
    return user_agents[random.randint(0,len(user_agents)-1)]

def reg_headers():
    #return {"User-Agent":user_agent_generator(),"Accept-Encoding":"gzip, deflate, br","Accept":"*/*","Accept-Language":"en-US,en;q=0.5"}
    return {"User-Agent":user_agent_generator(),"Accept":"*/*","Accept-Language":"en-US,en;q=0.5"}

def get_file(file):
    ls = []
    with open(file,"r") as f:
        for e in f:
            ls.append(e.rstrip())
    return ls

def get_request(domain):
    '''Make a get request to the "domain", and return it\'s contents.'''
    for _ in range(5):
        try:
            r = requests.get(domain, headers=reg_headers(), allow_redirects=False, timeout=(10,20))
        except Exception:
            if args.verb:
                print("[",clr("ERR","red"),"]",domain,"connection error!","                ",end="\r")
    try:
        if r == None:
            r = "None"
    except Exception:
        if args.verb:
            print("[",clr("ERR","red"),"]",domain,"returned 'None' value.")
        return "None"
    return r

def extract_juice(text, api_list, param_list, sensitive_list, extension_list, awskey_list, googlekey_list, githubkey_list, b64_list, endpoint_list, string_list, dir_list):
    '''Extract api endpoints, parameters, sensitive files, other files, 
    aws keys, google keys, github keys and base64 strings from text'''
    api_re = r"/v[0-9\.]/[\w\.\-/]+"
    param_re = r"(?<=[\?&])\w+(?==)|(?<=\.(?:[gs]et|has)\([\"'])\w+(?=[\"'])"
    sensitive_re = r"https?://[\w\.\-]+/[\w\-/]+\.(?:sql|config|conf|cfg|log|env|ini|bak|old|backup|csv|zip)"
    extension_re = r"https?://[\w\.\-]+/[\w\-/]+\.(?:xml|txt|json|php|asp|aspx|jsp|jspx)"
    aws_keys_re = r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,38}"
    google_keys_re = r"AIza[\w\-]{32,38}"
    github_keys_re = r"(?:[a-zA-Z0-9_\-]{2,}:)?ghp_[a-zA-Z0-9]{30,}"
    b64_re = r"(?:eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9\+/]+={0,2}"
    endpoint_re = r"https?://[\w\.\-]+/[\w\-/]+"
    string_re = r"(?<=[\"'])([a-zA-Z0-9]{,30}|_[a-zA-Z0-9]{,30}|[a-zA-Z0-9]{,20}_[a-zA-Z0-9]{,20})(?=[\"'])"
    dirs_re = r"(?<=[\"'])/[\w\-/]+(?=[\"'])"

    found_api = re.findall(api_re,text)
    found_param = re.findall(param_re,text)
    found_sensitive = re.findall(sensitive_re,text)
    found_extension = re.findall(extension_re,text)
    found_aws = re.findall(aws_keys_re,text)
    found_google = re.findall(google_keys_re,text)
    found_github = re.findall(github_keys_re,text)
    found_b64 = re.findall(b64_re,text)
    found_endpoints = re.findall(endpoint_re,text)
    found_strings = re.findall(string_re,text)
    found_dirs = re.findall(dirs_re,text)

    def in_list(found_ls,ls):
        for x in found_ls:
            if x not in ls:
                ls.append(x)
        return ls

    api_list = in_list(found_api,api_list)
    param_list = in_list(found_param,param_list)
    sensitive_list = in_list(found_sensitive,sensitive_list)
    extension_list = in_list(found_extension,extension_list)
    awskey_list = in_list(found_aws,awskey_list)
    googlekey_list = in_list(found_google,googlekey_list)
    githubkey_list = in_list(found_github,githubkey_list)
    b64_list = in_list(found_b64,b64_list)
    endpoint_list = in_list(found_endpoints,endpoint_list)
    string_list = in_list(found_strings,string_list)
    dir_list = in_list(found_dirs,dir_list)

    return api_list, param_list, sensitive_list, extension_list, awskey_list, googlekey_list, githubkey_list, b64_list, endpoint_list, string_list, dir_list

### SCRIPT
if __name__ == "__main__":
    # Get list of domains
    js_list = get_file(args.list)

    # Juice lists
    api_list = []
    param_list = []
    sensitive_list = []
    extension_list = []
    awskeys_list = []
    googlekeys_list = []
    githubkeys_list = []
    b64_list = []
    endpoint_list = []
    string_list = []
    dir_list = []

    # Now check each JS file once
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as exe:
        f1 = [exe.submit(get_request,js_list[x]) for x in range(len(js_list))]
        for comp in concurrent.futures.as_completed(f1):
            r = comp.result()
            count += 1
            try:
                if r.status_code == 200:
                    print("[",clr("?","yellow"),"]",r.url,"(",clr(f"{count}/{len(js_list)}","green"),")","                        ",end="\r")
                    api_list, param_list, sensitive_list, extension_list, awskeys_list, googlekeys_list, githubkeys_list, b64_list, endpoint_list = extract_juice(r.text, api_list, param_list, sensitive_list, extension_list, awskeys_list, googlekeys_list, githubkeys_list, b64_list, endpoint_list, string_list, dir_list)
                elif r.status_code == 401 or r.status_code == 403 or r.status_code == 429:
                    print("[",clr("!","red"),"]",r.url,"Error!",clr(r.status_code,"red"),"                      ",end="\r")
            except Exception:
                pass

    print()

    # Cleaning string list as it's a f'n mess
    string_blacklist = r"-apple-system-body|serif|sans|monospace|lpx|system_ui|[0-9]+px|div|span|absolute|Mutation|Query|[aA]rray|[sS]tring|[aA]ttribution|[wW]indow|[rR]ender|[iI]nput|[dD]ate|[mM]onth|[yY]ear|[hH]andle|is[A-Z][a-z]+|[tT]ext|[iI](mg|mage|con)|[eE]nabled|[kK]ey[wW]ord|[aA]xis|[oO]ffset|[sS](ort|croll)|[sS]vg|^[0-9]{3,}$|[vV][0-9][a-zA-Z]|^(show|should|on|[sSgG]et|[bB]efore|[aA]fter|put|post|patch|call|report|remove|clear|min|max|start|stop|keep|async|use)[A-Z]|^[A-Z]{2,3}$|^[a-z]{2}$|[sS]tyle|[pP]aram|^utm|[0-9]+x+[0-9]*|^\w{2}[\-_]\w{2}$|[dD]ay|[wW]eek|[aA]nimation|[aA]xis|[YSND]{3}|[hH]mm|[hH]eight|[wW]idth|[bB]utton|[pP]ointer|[Mm][Oo][Vv][eE]|[mM]illi|[hH]our|[sS]econd"

    clean_strings = []
    for s in string_list:
        if re.search(string_blacklist,s) == None:
            clean_strings.append(s)

    def mkfile(file,ls,txt):
        if len(ls) != 0:
            print("[",clr("+","green"),"]","Found",clr(len(ls),"magenta"),f"{txt}. \"{file}\" created!")
            with open(file,"w") as f:
                for x in ls:
                    f.write(f"{x}\n")
        else:
            print("[",clr("!","red"),"]","Found",clr(len(ls),"magenta"),f"{txt}.")

    # Print and create these lists
    mkfile("jfind_dirs.txt",dir_list,"directories")
    mkfile("jfind_params.txt",param_list,"parameters")
    mkfile("jfind_strings.txt",clean_strings,"strings")
    mkfile("jfind_endpoints.txt",endpoint_list,"endpoints")
    mkfile("jfind_api.txt",api_list,"API endpoints")
    mkfile("jfind_sensitive.txt",sensitive_list,"sensitive files")
    mkfile("jfind_otherext.txt",extension_list,"other files")
    mkfile("jfind_aws.txt",awskeys_list,"AWS keys")
    mkfile("jfind_google.txt",googlekeys_list,"Google keys")
    mkfile("jfind_github.txt",githubkeys_list,"Github keys")
    mkfile("jfind_b64.txt",b64_list,"Base64 strings")
