import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
import re
import pandas as pd
from pathlib import Path
import argparse
import dateutil.parser
from joblib import Parallel, delayed
import sys
from tqdm import tqdm
import subprocess

sys.setrecursionlimit(30000)

interpreter = "python" if os.name == 'nt' else "python3"

master_url = 'https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94'

out_dir_layers = Path("ScraperLayers")

def is_string_in_text(string, text):
	return True if re.compile(r'\b({0})\b'.format(string)).search(text) is not None else False

def infer_matrix(text):
    matrix_list = []
    # check by Tactics and Techniques IDs first (they are unique)
    # enterpise
    tactics_csv = pd.read_csv(Path("TTLists/enterprise_tactics.csv"))
    techniques_csv = pd.read_csv(Path("TTLists/enterprise_techniques.csv"))
    for i in range(0, tactics_csv.shape[0]):
        if is_string_in_text(tactics_csv.iat[i, 0], text):
            matrix_list.append('enterprise')
            break
    if 'enterprise' not in matrix_list:
        for i in range(0, techniques_csv.shape[0]):
            if is_string_in_text(techniques_csv.iat[i, 0], text):
                matrix_list.append('enterprise')
                break
    # ics
    tactics_csv = pd.read_csv(Path("TTLists/ics_tactics.csv"))
    techniques_csv = pd.read_csv(Path("TTLists/ics_techniques.csv"))
    for i in range(0, tactics_csv.shape[0]):
        if is_string_in_text(tactics_csv.iat[i, 0], text):
            matrix_list.append('ics')
            break
    if 'ics' not in matrix_list:
        for i in range(0, techniques_csv.shape[0]):
            if is_string_in_text(techniques_csv.iat[i, 0], text):
                matrix_list.append('ics')
                break
    # mobile
    tactics_csv = pd.read_csv(Path("TTLists/mobile_tactics.csv"))
    techniques_csv = pd.read_csv(Path("TTLists/mobile_techniques.csv"))
    for i in range(0, tactics_csv.shape[0]):
        if is_string_in_text(tactics_csv.iat[i, 0], text):
            matrix_list.append('mobile')
            break
    if 'mobile' not in matrix_list:
        for i in range(0, techniques_csv.shape[0]):
            if is_string_in_text(techniques_csv.iat[i, 0], text):
                matrix_list.append('mobile')
                break
    
    # if the list contains something then return it
    if matrix_list:
        return matrix_list
    
    # if all the previous fail, check if the text contains the words 'enterprise', 'mobile' or 'ics'
    if re.search(r'\benterprise\b', text, re.IGNORECASE):
        matrix_list.append('enterprise')
    if re.search(r'\bics\b', text, re.IGNORECASE):
        matrix_list.append('ics')
    if re.search(r'\bmobile\b', text, re.IGNORECASE):
        matrix_list.append('mobile')

    return matrix_list

def gather_info(url, T_search, t_search):
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'html.parser')
    date = soup.find('div', class_=['c-field--name-field-release-date', 'c-field--name-field-last-updated']).find('div', class_='c-field__content').find('time').string
    date = dateutil.parser.parse(date).strftime('%d/%m/%Y')
    id = soup.find('div', class_='c-field--name-field-alert-code').find('div', class_='c-field__content').string.replace(" ", "")
    title = soup.find('h1', class_='c-page-title__title').find('span').string
    text = soup.get_text()

    # set matrix type(s)
    matrix_type = infer_matrix(text)

    tactics_list = [[], [], []]
    techniques_list = [[], [], []]

    # build Navigator layer(s)
    for m in matrix_type:
        if m == 'enterprise':
            matrix_type_index = 0
            tactics_file = "TTLists/enterprise_tactics.csv"
            techniques_file = "TTLists/enterprise_techniques.csv"
        elif m == 'ics':
            matrix_type_index = 1
            tactics_file = "TTLists/ics_tactics.csv"
            techniques_file = "TTLists/ics_techniques.csv"
        elif m == 'mobile':
            matrix_type_index = 2
            tactics_file = "TTLists/mobile_tactics.csv"
            techniques_file = "TTLists/mobile_techniques.csv"
    
        tactics_dataset = pd.read_csv(Path(tactics_file))
        techniques_dataset = pd.read_csv(Path(techniques_file))

        #find all tactics
        for i in range(0, tactics_dataset.shape[0]):
            if T_search == 'id':
                if is_string_in_text(tactics_dataset.iat[i, 0], text):
                    tactics_list[matrix_type_index].append(tactics_dataset.iat[i, 0])
            elif T_search == 'name':
                if is_string_in_text(tactics_dataset.iat[i, 1], text):
                    tactics_list[matrix_type_index].append(tactics_dataset.iat[i, 0])
            else:
                if is_string_in_text(tactics_dataset.iat[i, 0], text) or is_string_in_text(tactics_dataset.iat[i, 1], text):
                    tactics_list[matrix_type_index].append(tactics_dataset.iat[i, 0])
        
        # find all techniques
        for i in range(0, techniques_dataset.shape[0]):
            if t_search == 'id':
                if is_string_in_text(techniques_dataset.iat[i, 0], text):
                    techniques_list[matrix_type_index].append(techniques_dataset.iat[i, 0])
            elif t_search == 'name':
                if is_string_in_text(techniques_dataset.iat[i, 1], text):
                    techniques_list[matrix_type_index].append(techniques_dataset.iat[i, 0])
            else:
                if is_string_in_text(techniques_dataset.iat[i, 0], text) or is_string_in_text(techniques_dataset.iat[i, 1], text):
                    techniques_list[matrix_type_index].append(techniques_dataset.iat[i, 0])

        # build layer, but only if there are found techniques
        if techniques_list[matrix_type_index]:
            os.makedirs(out_dir_layers, exist_ok=True)
            subprocess.run([interpreter, "report_analyzer.py",
                            "-i", url,
                            "-m", m[0],
                            "-l", "".join([id, "-", m]),
                            "-o", str(out_dir_layers / (id + "-" + m)),
                            "-t", techniques_file,
                            "-s", t_search])
    
    layer = [None, None, None]
    for m_idx, m in enumerate(['enterprise', 'ics', 'mobile']):
        filename = out_dir_layers / (id + "-" + m + ".json")
        if os.path.isfile(filename):
            with open(filename) as f:
                layer[m_idx] = f.read()
    
    return [id, title, date,url, tuple(matrix_type),
            tuple(tactics_list[0]), tuple(tactics_list[1]), tuple(tactics_list[2]),
            tuple(techniques_list[0]), tuple(techniques_list[1]), tuple(techniques_list[2]),
            layer[0], layer[1], layer[2]]
        

def main():
    parser = argparse.ArgumentParser(
        prog='scraper',
        description='Reads info from cybersecurity advisories and puts them in a CSV'
    )
    parser.add_argument('-t', choices=['id', 'name', 'both'], default='both', help='Search in the text by technique ID, by name or both')
    parser.add_argument('-T', choices=['id', 'name', 'both'], default='both', help='Search in the text by tactic ID, by name or both')
    options = vars(parser.parse_args())

    # load existent db
    df_old = pd.read_csv("db.csv", sep=';') if os.path.isfile("db.csv") else None
    
    # master_list must contain: url, date, code, title, TTP
    master_list = []

    r = requests.get(master_url)
    soup = BeautifulSoup(r.content, 'html.parser')
    href = soup.find('a', class_='c-pager__link--last')['href']
    num_of_pages = int(re.search(r'page=(\d+)', href).group(1))
    domain = urlparse(master_url).netloc

    backend = 'multiprocessing' if os.name == 'posix' else 'threading'

    for i in tqdm(range(0, num_of_pages+1)):
        page_url = 'https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94&page=' + str(i)

        r = requests.get(page_url)

        soup = BeautifulSoup(r.content, 'html.parser')
        s = soup.find('div', class_='c-view')
        content = s.find_all(class_='c-teaser__row')

        url_list = []
        for c in content:
            url_list.append("https://" + domain + c.find('a')['href'])

        try:
            page_list = Parallel(n_jobs=-1, backend=backend)(delayed(gather_info)(url, options['T'], options['t']) for url in url_list)
        except:
            try:
                page_list = Parallel(n_jobs=-1, backend='threading')(delayed(gather_info)(url, options['T'], options['t']) for url in url_list)
                backend = 'threading'
            except:
                page_list = [gather_info(url, options['T'], options['t']) for url in url_list]
        
        master_list += page_list

    df_new = pd.DataFrame(master_list,
                            columns=['Code',
                                    'Title',
                                    'Date',
                                    'URL',
                                    'Matrix',
                                    'Tactics (Enterprise)',
                                    'Tactics (ICS)',
                                    'Tactics (Mobile)',
                                    'Techniques (Enterprise)',
                                    'Techniques (ICS)',
                                    'Techniques (Mobile)',
                                    'Layer (Enterprise)',
                                    'Layer (ICS)',
                                    'Layer (Mobile)'])
    if df_old is not None:
        df_old = pd.concat([df_old, df_new]).drop_duplicates(keep='last',subset=['Code']).reset_index(drop=True)
    else:
        df_old = df_new
    df_old.to_csv("db.csv", sep=';', index=False)

if __name__ == '__main__':
    main()
