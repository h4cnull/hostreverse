#coding = utf-8

import re
import os
import sys
import requests
import dns.resolver
from fake_useragent import UserAgent

import warnings
warnings.filterwarnings("ignore")

def failed_log(host,reason):
	global rst_file_name_pre
	with open(rst_file_name_pre + "_failed_log.txt",'a+') as f:
		f.write("%s %s\n" % (host,reason))

def is_ip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",ip):
        return True
    return False

def multi_dns_resolver(domain,dns_servers):
	reverse_result = {domain:[]}
	for dnsip in dns_servers:
		my_resolver = dns.resolver.Resolver()
		my_resolver.nameservers = [dnsip]
		try:
			answer = my_resolver.query(domain,lifetime=3)
		except:
			continue
		for A in answer:
			if A.address not in reverse_result[domain]:
				reverse_result[domain].append(A.address)
	return reverse_result

def get_proxy(url):
	#https://github.com/jhao104/proxy_pool.git
	count = 0
	while count < 10:
		try:
			print("[-] Try to get porxy to %s " % url)
			proxy = requests.get("http://118.24.52.95/get/",timeout=2).json().get("proxy")
			format_proxy = {"https": "http://{}".format(proxy)}
			ua = UserAgent()
			headers = {'User-Agent': ua.random}
			response = requests.get(url,headers=headers,timeout=3,verify=False,proxies=format_proxy)
			if response.status_code == requests.codes.ok:
				print("[-] Find a porxy %s to %s " % (proxy,url))
				return format_proxy
		except Exception as e:
			#print(e)
			try:
				requests.get("http://118.24.52.95/delete/?proxy={}".format(proxy),timeout=2)
			except:
				pass
		count += 1
	print("[!] Did not find a porxy to %s " % url)
	return None

def parse_hackertarget_com(ip):

	global hackertarget_com_proxy

	result = []
	ua = UserAgent()
	headers = {"User-Agent":ua.random,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"}

	#获取name_of_nonce_field 设置post data
	try:
		page_content = requests.get("https://hackertarget.com/reverse-ip-lookup/",headers=headers,timeout=3,verify=False,proxies=hackertarget_com_proxy)
		page_content = bytes.decode(page_content.content)
		name_of_nonce_field = re.findall("</div><input type=\"hidden\" id=\"name_of_nonce_field\".*?value=\"([a-z\d]+)\" />",page_content)
	except Exception as e:
		failed_log(ip,"hackertarget.com get \"name_of_nonce_field\" error with " + str(e))
		return result
	data = {"theinput":ip,"thetest":"reverseiplookup","name_of_nonce_field":name_of_nonce_field,"_wp_http_referer":"%2Freverse-ip-lookup%2F"}
	
	try:
		page_content = requests.post("https://hackertarget.com/reverse-ip-lookup/",headers=headers,data=data,timeout=5,verify=False,proxies=hackertarget_com_proxy)
		page_content = bytes.decode(page_content.content)

		if "API count exceeded" in page_content:
			print("[-] hackertarget.com need proxy")
			hackertarget_com_proxy = get_proxy("https://hackertarget.com/reverse-ip-lookup/")
			if hackertarget_com_proxy:
				result = parse_hackertarget_com(ip)
				return result
			else:
				failed_log(ip, " hackertarget.com API count exceeded and cannot get porxy")

		result = re.findall("<pre id=\"formResponse\">([a-zA-Z\d\.\n]+)</pre>",page_content,re.DOTALL)
		if result:
			result = result[0].split()
	except Exception as e:
		failed_log(ip," hackertarget.com post data error with " + str(e))
	return result

def parse_tools_ipip_net(ip):

	global tools_ipip_net_proxy

	result = []
	ua = UserAgent()
	headers = {"Origin":"https://tools.ipip.net","Content-Type":"application/x-www-form-urlencoded","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3","Referer":"https://tools.ipip.net/ipdomain.php"}
	data = {"ip":ip}
	try:
		page_content = requests.post("https://tools.ipip.net/ipdomain.php",headers=headers,data=data,timeout=5,verify=False,proxies=tools_ipip_net_proxy)
		page_content = bytes.decode(page_content.content)
		if "javascript:history.back(-1)" in page_content:
			print("[-] tools.ipip.net need proxy")
			tools_ipip_net_proxy = get_proxy("https://tools.ipip.net/ipdomain.php")
			if tools_ipip_net_proxy:
				result = parse_tools_ipip_net(ip)
				return result
			else:
				failed_log(ip, " tools.ipip.net Query count exceeded and cannot get porxy")
		result = re.findall("<table class=\"table table-bordered\">.*?</table>",page_content,re.DOTALL)
		if result:
			result = re.findall("((?:[a-zA-Z\d-]+\.)+[a-zA-Z]+)", result[0], re.DOTALL)
	except Exception as e:
		failed_log(ip," tools.ipip.net post data error with " + str(e))
	return result

def ip_parser(ip):
	reverse_result = {ip:[]}
	reverse_result[ip] = list(set(parse_hackertarget_com(ip) + parse_tools_ipip_net(ip)))
	return reverse_result

if __name__ == "__main__":
	try:
		filename = sys.argv[1]
		rst_file_name_pre = os.path.split(filename)[1].split(".")[0]
	except Exception as e:
		print(e)
		print("[+] Usage: %s hostfile" % sys.argv[0])
		sys.exit(0)
	
	dns_servers = []
	with open(".\\dns\\dns_servers.txt", 'r') as f:
		dns_servers = list(set([line.strip().split()[1] for line in f.readlines()]))

	host_list = []
	with open(filename,'r') as f:
		host_list = list(set([line.strip() for line in f.readlines()]))
	
	hackertarget_com_proxy = None
	tools_ipip_net_proxy = None
	
	result = {}
	for host in host_list:
		print("[-] Try to reverse %s" % host)
		if  is_ip(host):
			result.update(ip_parser(host))
		else:
			result.update(multi_dns_resolver(host,dns_servers))
	print()
	for key in result:
		if not result[key]:
			with open(rst_file_name_pre+"_not_found.txt",'a+') as f:
				f.write(key+"\n")
			continue
		rst = ""
		for line in result[key]:
			rst = rst + line + " "
		print("[+] %s %s" % (key,rst))
		with open(rst_file_name_pre+"_found_result.txt",'a+') as f:
			f.write("%s %s\n" % (key,rst))