import time
import json
import requests
import urllib
import json
		
def domainReport(domn):
	subdomain_list=[]
	ip_list=[]
	url_list=[]
	
	params = {'apikey':'', 'domain':domn}
	headers = {
	  "Accept-Encoding": "gzip, deflate",
  	  "User-Agent" : "gzip,  My python example client or username"
	}
	response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report',  params=params, headers=headers)
	#print(response)
	res = json.loads(response.content)
	print('\033[1m\n\nSubDomain :\n\n\033[0m')
	try:
		for i in res['subdomains']:
			subdomain_list.append(i)
		for i in subdomain_list:
			print(i)

	except:
		print("no subdomain")	
	
	for i in res['resolutions']:
		ip_list.append(i)
	
	print('\033[1m\n\nIP :\n\n\033[0m')
	
	for i in ip_list:
		print(i['ip_address'])
	for i in res['detected_urls']:
		url_list.append(i)
	
	print('\033[1m\n\nURL :\n\n\033[0m')
	
	for i in url_list:
		print(i['url'])

def main():
	limit = 4
	
	fo = open("input.txt", "r")
	content = fo.readlines()
	chunks = [content[x:x+limit] for x in range(0, len(content), limit)]
		
	for chunk in chunks:
		for dom in chunk:
					
			d1 = dom.strip()
			print('\033[1m\n\nDomain :\n\n\033[0m')	
			print(d1)		
			domainReport(d1)
		time.sleep(60)

				
if __name__ == "__main__":
    main()
