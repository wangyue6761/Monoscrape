from scraper import Scraper
import json
import os
import re
import base64
import datetime

project_path = "chromium_all_poc"
issuesjson_path = "ALL_issues_json"

def find_cve_id(labels):
    pattern = r'CVE-\d{4}-\d{4,7}'
    for label in labels:
        label = label["label"]
        matchcve = re.findall(pattern,label)
        if matchcve:
            return matchcve[0]
    return ""

def store_pocfiles(issue_path,filename, data):
    decoded_data = base64.b64decode(data.encode('utf-8'))
    with open(os.path.join(issue_path, filename), "wb") as file:
        file.write(decoded_data)

def parseaspetct(single_issue):
    aspect = {}
    aspect['localId'] = str(single_issue["localId"])
    aspect['cveid'] = find_cve_id(single_issue["labelRefs"])
    aspect['project'] = single_issue["projectName"]
    aspect['comment'] = ""
    aspect['summary'] = single_issue['summary']
    aspect['reporter'] = single_issue['reporterRef']['displayName']
    try:
        aspect['component'] = single_issue["componentRefs"]
    except:
        aspect['component'] = []
    aspect['OS'] = []
    if "fieldValues" in single_issue.keys():
        for field in single_issue["fieldValues"]:
            if field["fieldRef"]["type"] == "OS":
                aspect['OS'].append(field['value'])
    aspect['openedTime'] = datetime.datetime.fromtimestamp(single_issue['openedTimestamp']).strftime("%Y-%m-%d %H:%M:%S")
    return aspect

def store_desfiles(file_name):
    with open(os.path.join(issuesjson_path, file_name), "r") as file:
        all_issues = json.load(file)
    for single_issue in all_issues:
        if "comments" in single_issue:
            aspect = parseaspetct(single_issue)
            try:
                aspect['comment'] = single_issue["comments"][0]["content"]
            except:
                continue
            issue_path = os.path.join(project_path, aspect['cveid']+ "_Issue"+aspect['localId'])
            os.makedirs(issue_path, exist_ok=True)
            with open(os.path.join(issue_path, "aspect"+aspect['localId']+".json"), "w") as file:
                json.dump(aspect, file, indent=4)
            for comment in single_issue['comments']:
                if "attachments" in comment:
                    for attachment in comment["attachments"]:
                        if "data" in attachment:
                            store_pocfiles(issue_path,attachment["filename"],attachment['data'])

def extract_files():
    print("STEP2 Extract")
    file_names = os.listdir(issuesjson_path)
    for file_name in file_names:
        store_desfiles(file_name)
    print("End")
        
def all_cve_issues(batch_size):
    print("STEP1 Scrape")
    scrape = Scraper()
    next_batch = 1
    have_count = 0 ## 中断灵活调整,失败的批次文件
    condition = ""  ## 中断灵活调整，失败的批次文件第一个id，或者上一个批次最后一个id
    while(next_batch):
        print("\nIssues Count:" + str(have_count + (next_batch-1)*batch_size) + "->" + str(have_count + next_batch*batch_size-1))
        query = scrape.query_builder(num_items=batch_size, with_strings=condition)
        output = scrape.get_all(query)
        json_name = "cve_issues" + "_" + str(have_count + (next_batch-1)*batch_size) + "_" + str(have_count + next_batch*batch_size-1) + ".json"
        with open(os.path.join(issuesjson_path, json_name), "w") as file:
            json.dump(output, file, indent=4)
        if(len(output)>=batch_size):
            next_batch += 1
            condition = "id<" + str(output[-1]["localId"])
        else:
            next_batch = 0

if __name__ == "__main__":
    batch_size = 100
    os.makedirs(issuesjson_path, exist_ok=True)
    all_cve_issues(batch_size)
    extract_files()