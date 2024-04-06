import pandas as pd
import argparse
import os
from pathlib import Path

names = ['enterprise', 'mobile', 'ics']

urlt1 = r'https://attack.mitre.org/techniques/enterprise/'
urlt2 = r'https://attack.mitre.org/techniques/mobile/'
urlt3 = r'https://attack.mitre.org/techniques/ics/'
urlT1 = r'https://attack.mitre.org/tactics/enterprise/'
urlT2 = r'https://attack.mitre.org/tactics/mobile/'
urlT3 = r'https://attack.mitre.org/tactics/ics/'

dirname = Path("TTLists")

def build_dict(matrix, type):
    if matrix == 'e':
        if type == 't':
            url_l = [urlt1]
        else:
            url_l = [urlT1]
    elif matrix == 'm':
        if type == 't':
            url_l = [urlt2]
        else:
            url_l = [urlT2]
    elif matrix == 'i':
        if type == 't':
            url_l = [urlt3]
        else:
            url_l = [urlT3]
    else:
        if type == 't':
            url_l = [urlt1, urlt2, urlt3]
        else:
            url_l = [urlT1, urlT2, urlT3]
    
    compendium = None
    for idx, url in enumerate(url_l):
        print("Processing: " + url)
        tables = pd.read_html(url)
        df = tables[0]

        if matrix == 'e':
            name = names[0]
        elif matrix == 'm':
            name = names[1]
        elif matrix == 'i':
            name = names[2]
        else:
            name = names[idx]

        if type == 't':
            df = df.drop(columns=['ID', 'Description'])
            tmp_id = 0
            for i in range(0, df.shape[0]):
                if not df.iat[i, 0][0] == '.':
                    tmp_id = df.iat[i, 0]
                else:
                    df.iat[i, 0] = ''.join([str(tmp_id), df.iat[i, 0]])
            filename = dirname / ''.join([name, '_techniques.csv'])
        else:
            df = df.drop(columns=['Description'])
            filename = dirname / ''.join([name, '_tactics.csv'])

        os.makedirs(dirname, exist_ok=True)
        df.to_csv(filename, index=False)
        if matrix == 'a':
            compendium = pd.concat([compendium, df]).drop_duplicates().reset_index(drop=True)
    if compendium is not None:
        if type == 't':
            filename = dirname / "compendium_techniques.csv"
        else:
            filename = dirname / "compendium_tactics.csv"
        compendium.to_csv(filename, index=False)

def main():
    parser = argparse.ArgumentParser(
        prog='build_dictionary',
        description='Builds a dictionary of techniques or tactics to be used with the report analyzer'
    )
    parser.add_argument('-t', choices=['e', 'm', 'i', 'a'], default='a', help='Choose which technique dictionary you want to build from (e)nterprise, (m)obile, (i)cs or (a)ll')
    parser.add_argument('-T', choices=['e', 'm', 'i', 'a'], default='a', help='Choose which tactic dictionary you want to build from (e)nterprise, (m)obile, (i)cs or (a)ll')
    options = vars(parser.parse_args())
    build_dict(options['t'], 't')
    build_dict(options['T'], 'T')


if __name__ == '__main__':
    main()
