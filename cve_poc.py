from scraper import Scraper
import json
import os
import re
import base64

project_path = "chromiumpoc"

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

def extract_files():
    print("STEP2 Extract")
    with open(os.path.join(project_path, "all_cve_issues"+".json"), "r") as file:
        all_issues = json.load(file)
    for single_issue in all_issues:
        if "comments" in single_issue:
            localId = str(single_issue["localId"])
            cveid = find_cve_id(single_issue["labelRefs"])
            description = single_issue["comments"][0]["content"]
            issue_path = os.path.join(project_path,cveid+ "_"+localId)
            os.makedirs(issue_path, exist_ok=True)
            with open(os.path.join(issue_path, "description"+localId+".txt"), "w") as file:
                file.write(description)
            for comment in single_issue['comments']:
                if "attachments" in comment:
                    for attachment in comment["attachments"]:
                        if "data" in attachment:
                            store_pocfiles(issue_path,attachment["filename"],attachment['data'])
    print("End")
        

def all_cve_issues():
    print("STEP1 Scrape")
    scrape = Scraper()
    query = scrape.query_builder(num_items=10, labels="CVE_description-submitted")
    output = scrape.get_all(query)
    with open(os.path.join(project_path, "all_cve_issues"+".json"), "w") as file:
        json.dump(output, file, indent=4)


if __name__ == "__main__":
    all_cve_issues()
    extract_files()