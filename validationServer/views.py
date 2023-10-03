from django.shortcuts import render
from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

# For Validation
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
import whois
import csv
import socket
import pandas as pd
import ssl
import requests
import re

@api_view(['POST'])
def validation (request):

    if request.method == 'POST':
        print("POST")

        # Parsing the URL

        try:
            url = request.data.get('url', '')
            domain,url_parse, domaintld, x = parsingURL(url) # get the domain
            soup, response = soupURL(url)
            whois_response = WHOIS(domain)

        

            # Call the rules
            result_anchor = url_anchor (soup, domain, url)
            result_SSL = SSL(url_parse, domaintld)
            result_links_to_page = links_pointing_to_page(response);
            result_prefix = prefix(domain)
            result_subDomain = findSubdomain(domain)
            result_regLenth = regLength(whois_response)
            result_script_tags = link_in_script(domain, soup, url)
            result_rank = websiteRank(x)

            print("D",domain)
            # Call the condition

            validationResult  = condition(
                result_anchor,
                result_SSL,
                result_links_to_page,
                result_prefix,
                result_subDomain,
                result_regLenth,
                result_script_tags,
                result_rank

            )

            print(validationResult)

            character_count = len(url)
            return Response({'result': validationResult})
        
        except:
            return Response(request.data.errors, status=400)

    # return HttpResponse("Hello World")
# Create your views here.

def parsingURL(url):

    try:
        url_parse = urlparse(url)
        domain = url_parse.netloc
        # print(domain)

        parseURL = tldextract.extract(url)
        urlDomain = str(parseURL.domain)
        # print(urlDomain)

        urlSuffix = str(parseURL.suffix)
        # print(urlSuffix)
        domaintld = urlDomain + "." + urlSuffix

        api = "https://tranco-list.eu/api/ranks/domain/"

        x = api + domaintld

        print(x)

        return domain, url_parse, domaintld, x
    
    except:
        
        return None


def soupURL(url):
    try:
        
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        return soup, response

    except:
        return None

def WHOIS(domain):
    
    try:
        whois_response = whois.whois(domain)
    
    except:
        
        return None



def condition(
        result_SSL, 
        result_anchor,
        result_links_to_page,
        result_prefix,
        result_subDomain,
        result_regLenth,result_script_tags,
        result_rank
        ):

    if result_SSL == 0 and result_anchor == -1:  # 1 PART

            # print("Phishing")
        return -1

    elif result_SSL == 0 and result_links_to_page == 1:  # 2 PART

        return -1
    
    elif result_SSL == -1 and result_anchor == -1 and result_prefix == -1:  # 5 PART

        return -1   
    
    elif result_SSL == 0 and result_links_to_page == 0 and result_subDomain == 0:  # 8 PART

        return -1  
    
    elif result_SSL == -1 and result_anchor == -1:  # 3 JRIP

        return -1      

    elif result_SSL == -1 and result_anchor == 0:  # 4 JRIP

        return -1  
    
    elif (
    result_SSL == -1
    and result_regLenth == 1
    and result_script_tags == 0
    and result_links_to_page == 0
    ):
        
        return -1
    

    elif result_rank == 0 and result_anchor == -1:
        return -1
    

    elif (
    result_rank == 0
    and result_anchor == 0
    and result_subDomain == 0
    and result_script_tags == 1
    ):
        
        return -1
    
    elif result_SSL == 0:

        return -1

         
    else:
         return 1
        



def url_anchor(soup, domain, url):  # URL ANCHOR

    try:

        count = 0
        unsafe = 0

        # Find all anchor link
        for a in soup.find_all("a", href=True):

            # find all empty link
            if (
                "#" in a["href"]
                or "javascript" in a["href"].lower()
                or "mailto" in a["href"].lower()
                or not (url in a["href"] or domain in a["href"])
            ):
                unsafe += 1
            count += 1

        # print("Unsafe", unsafe)
        # print("Count ", count)

        try:
            percentage = unsafe / float(count) * 100

            if percentage < 31.0:

                print("Anchor: Legitimate")
                return 1

            elif (percentage >= 31.0) and (percentage < 67.0):

                print("Anchor: Suspicious")
                return 0

            else:
                print("Anchor: Phishing")
                return -1

            # print("Percentage: ", percentage)

        except:
            print("Anchor: Phishing Error")
            return -1

    except:

        print("Anchor: Phishing Error")
        return -1
        # return "Safe"cls

def SSL(url_parse, hostname):  # SSL or HTTPS

    try:

        https = url_parse.scheme

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

            subject = dict(x[0] for x in cert["subject"])
            issued_to = subject["commonName"]
            issuer = dict(x[0] for x in cert["issuer"])
            issued_by = issuer["commonName"]
            issued_by_org = issuer["organizationName"]
            issued_by_org = str(issued_by_org)

     
        if "https" in https and readCSV(issued_by_org) == 1:

            print("SSL: Legitimate")
            return 1

        elif "https" in https and readCSV(issued_by_org) == 0:

            print("SSL: Suspicious")
            return 0
        else:

            print("SSL: Phishing")
            return -1

    except:
        print("SSL: Phishing Except")
        return -1    
    


def readCSV(ca_provider):

    path = "C:/KEN/Server/rules-main/list_of_org.csv"
    try:
        df = pd.read_csv(path)

        result = df["CA Owner"].str.contains(ca_provider).any()  # Output : True
        x = bool(result)

        if x:

            return 1
        else:

            return 0
    except:

        print("CSV error")


def links_pointing_to_page(response):  # Links Pointing to Page

    try:
        no_of_links = len(re.findall(r"<a href=", response.text))

        # print(no_of_links)
        if no_of_links == 0:

            print("LPTP: Legitimate")
            return 1

        elif no_of_links <= 2:

            print("LPTP: Suspicious")
            return 0

        else:
            print("LPTP: Phishing")
            return -1
    except:
        print("LPTP: Phishing")
        return -1

def prefix(domain):  # With hypen

    try:

        match = re.findall("\-", domain)

        if match:
            print("Prefix: Phishing")
            return -1

        print("Prefix: Legitimate")
        return 1

    except:
        print("Prefix: Phishing")
        return -1


def findSubdomain(url):  # Many Subdomain

    dot_count = len(re.findall("\.", url))

    if dot_count == 2:

        print("SubDomain: Legitimate")
        return 1

    elif dot_count == 3:

        print("SubDomain: Suspicious")
        return 0

    else:
        print("SubDomain: Phishing")
        return -1

def regLength(whois_response):  # Registration of Domain

    try:
        ex_date = whois_response.expiration_date
        cr_date = whois_response.creation_date

        try:
            if len(ex_date):

                ex_date = ex_date[0]

        except:

            pass

        try:
            if len(cr_date):
                cr_date = cr_date[0]

        except:
            pass

        age = (ex_date.year - cr_date) * 12 + (ex_date.month - cr_date.month)

        if age >= 12:
            return 1

        else:
            return -1
    except:
        return -1
    

def link_in_script(domain, soup, url):  # Link to Sripting Tags
    try:
        i, success = 0, 0

        for link in soup.find_all("link", href=True):
            dots = [x.start(0) for x in re.finditer("\.", link["href"])]
            if url in link["href"] or domain in link["href"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for script in soup.find_all("script", src=True):
            dots = [x.start(0) for x in re.finditer("\.", script["src"])]
            if url in script["src"] or domain in script["src"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        try:
            percentage = success / float(i) * 100
            # print(percentage)
            if percentage < 17.0:
                print("LinkScript: Legitimate")
                return 1
            elif (percentage >= 17.0) and (percentage < 81.0):
                print("LinkScript: Suspicious")
                return 0
            else:
                print("LinkScript: Phishing")
                return -1
        except:
            print("LinkScript: Suspicious Error 1")
            return 0
    except:
        print("LinkScript: Phishing Error 1")
        return -1

def websiteRank(x):

    rank = ""

    try:
        response = requests.get(x)
        json_data = response.json()
        data = json_data.get("ranks", [])

        num_items_to_display = 1
        for i, item in enumerate(data[:num_items_to_display], 1):

            rank = item.get("rank")
            date = item.get("date")

        if int(rank) < 10000 and int(rank) > 0:

            print("Rank: Legitimate")
            return 1

        else:
            print("Rank: Suspicious")
            return 0

    except:
        print("Rank: Phishing")
        return -1