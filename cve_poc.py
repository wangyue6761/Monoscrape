from scraper import Scraper
import json
import os
import re
import base64

project_path = "chromium_cve_poc"
issuesjson_path = os.path.join(project_path, "A_issues_json")

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

def store_desfiles(file_name):
    with open(os.path.join(issuesjson_path, file_name), "r") as file:
        all_issues = json.load(file)
    for single_issue in all_issues:
        if "comments" in single_issue:
            localId = str(single_issue["localId"])
            cveid = find_cve_id(single_issue["labelRefs"])
            try:
                description = single_issue["comments"][0]["content"]
            except:
                continue
            issue_path = os.path.join(project_path,"Issue"+localId+ "_"+cveid)
            os.makedirs(issue_path, exist_ok=True)
            with open(os.path.join(issue_path, "description"+localId+".txt"), "w") as file:
                file.write(description)
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
    have_count = 2528 ## 中断灵活调整,失败的批次文件
    condition = "id<=114911"  ## 中断灵活调整，失败的批次文件第一个id，或者上一个批次最后一个id
    while(next_batch):
        print("\nIssues Count:" + str(have_count + (next_batch-1)*batch_size) + "->" + str(have_count + next_batch*batch_size-1))
        query = scrape.query_builder(num_items=batch_size, labels="CVE_description-submitted", with_strings=condition)
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