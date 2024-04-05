import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
import re
import pandas as pd

master_url = 'https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94'

domain = urlparse(master_url).netloc

r = requests.get(master_url)

soup = BeautifulSoup(r.content, 'html.parser')
s = soup.find('div', class_='c-view')
content = s.find_all(class_='c-teaser__row')

url_list = []
for c in content:
    url_list.append("https://" + domain + c.find('a')['href'])


# master_list must contain: url, date, code, title, TTP
df_old = pd.read_csv("db.csv", sep=';') if os.path.isfile("db.csv") else None
master_list = []
for url in url_list:
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')
    date = soup.find('div', class_=['c-field--name-field-release-date', 'c-field--name-field-last-updated']).find('div', class_='c-field__content').find('time').string
    id = soup.find('div', class_='c-field--name-field-alert-code').find('div', class_='c-field__content').string
    title = soup.find('h1', class_='c-page-title__title').find('span').string
    # set type, find all tactics, find all techniques, build json
    tactics_list = []
    techniques_list = []
    matrix_type = None
    if re.search(r'\benterprise\b', r.text, re.IGNORECASE):
        matrix_type = 'enterprise'
        tactics_csv = pd.read_csv("enterprise_tactics.csv")
        techniques_csv = pd.read_csv("enterprise_techniques.csv")
        os.system("python3 Analyzer.py -i " + url + " -o " + id + " -t enterprise_techniques.csv")
    elif re.search(r'\bics\b', r.text, re.IGNORECASE):
        matrix_type = 'ics'
        tactics_csv = pd.read_csv("ics_tactics.csv")
        techniques_csv = pd.read_csv("ics_techniques.csv")
        os.system("python3 Analyzer.py -i " + url + " -m i -o " + id + " -t ics_techniques.csv")
    elif re.search(r'\bmobile\b', r.text, re.IGNORECASE):
        matrix_type = 'mobile'
        tactics_csv = pd.read_csv("mobile_tactics.csv")
        techniques_csv = pd.read_csv("mobile_techniques.csv")
        os.system("python3 Analyzer.py -i " + url + " -m m -o " + id + " -t mobile_techniques.csv")
    for i in range(0, tactics_csv.shape[0]):
        if tactics_csv.iat[i, 0] in r.text or tactics_csv.iat[i, 1]:
            tactics_list.append(tactics_csv.iat[i, 0])
    for i in range(0, techniques_csv.shape[0]):
        if techniques_csv.iat[i, 0] in r.text or techniques_csv.iat[i, 1]:
            techniques_list.append(techniques_csv.iat[i, 0])
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