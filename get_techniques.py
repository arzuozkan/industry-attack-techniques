import requests
from bs4 import BeautifulSoup
import json
import sys
import os

#unused
def get_data(url,table_class="table table-bordered table-alternate mt-2"):
    pass

if len(sys.argv)<1:
	print("Enter a sector name")
	exit(0)
else:
	apt_list=[]
	sector=sys.argv[1]

# json file can be downloaded https://apt.etda.or.th/cgi-bin/listgroups.cgi
with open("threatgroupall.json","r") as json_file:
		group=json.load(json_file)
    
print("apt group list for sector:", sector)
for i in range(0, len(group["values"])):
    try:
        observed_sectors = [sector.lower() for sector in group["values"][i]["observed-sectors"]]
        if sector in observed_sectors:
            actor = group["values"][i]["actor"]
            #print(actor)
            apt_list.append(actor)
    except KeyError as e:
        continue
with open(f"apt_list_{sector}.txt","w") as apt_file: 
    for i in apt_list:
        apt_file.write(i+"\n")
        

url = "https://attack.mitre.org/groups/"

#data_by_headers=get_data(url)
response = requests.get(url)
mgroups_by_headers = []

if response.status_code == 200:
    soup = BeautifulSoup(response.content, "html.parser")

    table=soup.find('table')
    headers = [header.text for header in table.find('tr').find_all('th')]

    rows = soup.find_all('tr')[1:] 
    table_data = []
    for row in rows:
        row_data = [cell.text for cell in row.find_all('td')]
        table_data.append(row_data)

    
    for row in table_data:
        mgroups_by_headers.append(dict(zip(headers, row)))


if not os.path.exists("allthreats.txt"):
    with open("allthreats.txt","w") as allthreats:
        for g in mgroups_by_headers:
            allthreats.write(g['Name'].lower().strip().replace(" ","")+"\n")
            
i=1
group_id=[]
#found=False
print("*****MITRE ATT&CK groups******")
with open(f"mitre_attack_apt_{sector}.txt","w") as mitre_group_file:
    for actor in apt_list:
        for a in actor.split(","):
            for group in mgroups_by_headers:#[0:int(len(data_by_headers)/13)]:
                if group["Name"].lower().strip().replace(" ","") == a.lower().strip().replace(" ",""):
                    print(i,a)
                    group_id.append(f"{group['ID'].strip()}:{group['Name'].strip()}")
                    mitre_group_file.write(f"{a}\n")
                    i=i+1
                    #found=True
                    break
            #if found:
            #    break    


print("MITRE ATTACK Techniques of APT Groups based on given sector:\n")
with open(f"techniques_{sector}_sector.txt","w") as output_file:
    for group in group_id:
        id,threat=group.split(":")
        print("********************************************************")
        print(id,"-",threat)
        output_file.write(threat+"\n")

        techniques_url=f"https://attack.mitre.org/groups/{id}/"
        response = requests.get(techniques_url)
        html_content = response.content

        soup = BeautifulSoup(html_content, 'html.parser')

        table_class = 'table techniques-used background table-bordered'
        desired_table = soup.find('table', class_=table_class)

        techniques = []
        if desired_table:
            rows = desired_table.find_all('tr')[1:]
            for row in rows:
                cells = row.find_all(['th', 'td'])  # Both th and td elements contain data
                row_data = [cell.text.strip() for cell in cells]
                techniques.append(row_data)
            
            table_data = []
            for row in rows:
                row_data = [cell.text for cell in row.find_all('td')]
                table_data.append(row_data)

        for t in techniques:
            if t[2].startswith("."):#any(char.isdigit() for char in t[2]):
                print(t[3])
                output_file.write(t[3]+"\n")
            else:
                print(t[2])
                output_file.write(t[2]+"\n")
        output_file.write("\n\n")
