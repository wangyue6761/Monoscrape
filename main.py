from scraper import Scraper
import json
import os

bugid = "1482602"
project_path = "chromiumpoc"
bugid_path = os.path.join(project_path, bugid)
os.makedirs(bugid_path, exist_ok=True)

scrape = Scraper()

query = scrape.query_builder(num_items=1000000, with_strings="id=1482602")
output = scrape.get_all(query)

with open(os.path.join(bugid_path, bugid+".json"), "w") as des:
    json.dump(output, des, indent=4)