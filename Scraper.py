import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
import re
import pandas as pd
from pathlib import Path

def is_string_in_text(string, text):
	return True if re.compile(r'\b({0})\b'.format(string)).search(text) is not None else False

master_url = 'https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94'

def main():
    domain = urlparse(master_url).netloc

    r = requests.get(master_url)

    soup = BeautifulSoup(r.content, 'html.parser')
    s = soup.find('div', class_='c-view')
    content = s.find_all(class_='c-teaser__row')

    url_list = []
    for c in content:
        url_list.append("https://" + domain + c.find('a')['href'])

    # load existent db
    df_old = pd.read_csv("db.csv", sep=';') if os.path.isfile("db.csv") else None
    # master_list must contain: url, date, code, title, TTP
    master_list = []
    for url in url_list:
        print("Contacted url:" + url)
        r = requests.get(url)
        soup = BeautifulSoup(r.content, 'html.parser')
        date = soup.find('div', class_=['c-field--name-field-release-date', 'c-field--name-field-last-updated']).find('div', class_='c-field__content').find('time').string
        id = soup.find('div', class_='c-field--name-field-alert-code').find('div', class_='c-field__content').string
        title = soup.find('h1', class_='c-page-title__title').find('span').string
        # set matrix type, find all tactics, find all techniques, build json
        tactics_list = []
        techniques_list = []
        matrix_type = None
        if re.search(r'\benterprise\b', r.text, re.IGNORECASE):
            matrix_type = 'enterprise'
            tactics_csv = pd.read_csv(Path("TTLists/enterprise_tactics.csv"))
            techniques_csv = pd.read_csv(Path("TTLists/enterprise_techniques.csv"))
            os.system("python3 Analyzer.py -i " + url + " -o " + id + " -t TTLists/enterprise_techniques.csv")
        elif re.search(r'\bics\b', r.text, re.IGNORECASE):
            matrix_type = 'ics'
            tactics_csv = pd.read_csv(Path("TTLists/ics_tactics.csv"))
            techniques_csv = pd.read_csv(Path("TTLists/ics_techniques.csv"))
            os.system("python3 Analyzer.py -i " + url + " -m i -o " + id + " -t TTLists/ics_techniques.csv")
        elif re.search(r'\bmobile\b', r.text, re.IGNORECASE):
            matrix_type = 'mobile'
            tactics_csv = pd.read_csv(Path("TTLists/mobile_tactics.csv"))
            techniques_csv = pd.read_csv(Path("TTLists/mobile_techniques.csv"))
            os.system("python3 Analyzer.py -i " + url + " -m m -o " + id + " -t TTLists/mobile_techniques.csv")
        print("---FOUND TACTICS---")
        for i in range(0, tactics_csv.shape[0]):
            if is_string_in_text(tactics_csv.iat[i, 0], r.text) or is_string_in_text(tactics_csv.iat[i, 1], r.text):
                tactics_list.append(tactics_csv.iat[i, 0])
                print(" - " + tactics_csv.iat[i, 0] + "(" + tactics_csv.iat[i, 1] + ")")
        print("---FOUND TECHNIQUES---")
        for i in range(0, techniques_csv.shape[0]):
            if is_string_in_text(techniques_csv.iat[i, 0], r.text): #or is_string_in_text(techniques_csv.iat[i, 1], r.text):
                techniques_list.append(techniques_csv.iat[i, 0])
                print(" - " + techniques_csv.iat[i, 0] + "(" + techniques_csv.iat[i, 1] + ")")
        if matrix_type is not None:
            with open(id+".json") as f:
                layer = f.read()
        else:
            layer = None
        master_list.append([id, title, date, url, matrix_type, tuple(tactics_list), tuple(techniques_list), layer])
        df_new = pd.DataFrame(master_list, columns=['Code', 'Title', 'Date', 'URL', 'Matrix', 'Tactics', 'Techniques', 'Layer'])
        if df_old is not None:
            df_old = pd.concat([df_old, df_new]).drop_duplicates().reset_index(drop=True)
        else:
            df_old = df_new
        df_old.to_csv("db.csv", sep=';')

if __name__ == '__main__':
    main()