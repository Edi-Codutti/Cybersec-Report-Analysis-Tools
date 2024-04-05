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

urls = [urlt1, urlt2, urlt3, urlT1, urlT2, urlT3]

def build_dict(url_i_l):
    for i in url_i_l:
        print("Processing: " + urls[i])
        tables = pd.read_html(urls[i])
        df = tables[0]

        if i in range(0, 3):
            df = df.drop(columns=['ID', 'Description'])
            tmp_id = 0
            for j in range(0, df.shape[0]):
                if not df.iat[j, 0][0] == '.':
                    tmp_id = df.iat[j, 0]
                else:
                    df.iat[j, 0] = ''.join([str(tmp_id), df.iat[j, 0]])
            filename = dirname / "".join([names[i], '_techniques.csv'])
        else:
            df = df.drop(columns=['Description'])
            filename = dirname / "".join([names[i%3], '_tactics.csv'])

        os.makedirs(dirname, exist_ok=True)
        df.to_csv(filename, index=False)

def main():
    parser = argparse.ArgumentParser(
        prog='build_dictionary',
        description='Builds a dictionary of techniques or tactics to be used with the report analyzer'
    )
    parser.add_argument('-t', choices=['e', 'm', 'i', 'a'], default='a', help='Choose which technique dictionary you want to build from (e)nterprise, (m)obile, (i)cs or (a)ll')
    parser.add_argument('-T', choices=['e', 'm', 'i', 'a'], default='a', help='Choose which tactic dictionary you want to build from (e)nterprise, (m)obile, (i)cs or (a)ll')
    options = vars(parser.parse_args())
    url_idx_list = []
    if options['t'] == 'e':
        url_idx_list.append(0)
    elif options['t'] == 'm':
        url_idx_list.append(1)
    elif options['t'] == 'i':
        url_idx_list.append(2)
    else:
        url_idx_list += [0, 1, 2]
    if options['T'] == 'e':
        url_idx_list.append(3)
    elif options['T'] == 'm':
        url_idx_list.append(4)
    elif options['T'] == 'i':
        url_idx_list.append(5)
    else:
        url_idx_list += [3, 4, 5]
    build_dict(url_idx_list)


if __name__ == '__main__':
    main()
