import pandas as pd
import argparse
from pathlib import Path
import re

TTDir = Path('TTLists')
TTFiles = ['compendium_tactics.csv', 'compendium_techniques.csv']

def is_string_in_text(string, text):
	return True if re.compile(r'\b({0})\b'.format(string)).search(text) is not None else False

def main():
    parser = argparse.ArgumentParser(
        prog='db_analyzer',
        description='Analyzer results of CISA scraper'
    )
    parser.add_argument('-i', required=True, help='Database input file in CSV format, result of scraper.py')
    parser.add_argument('-y', type=int, default=0, help='Year to specify for the counting. If unspecified the program will count globally')
    parser.add_argument('-t', default=None, help='Tactic or technique to count. If unspecified it will count all tactics and all techniques')
    options = vars(parser.parse_args())
    database = pd.read_csv(options['i'], sep=';')
    database['Date'] = pd.to_datetime(database['Date'], dayfirst=True)

    if options['y'] != 0:
        database = database[database['Date'].dt.year == options['y']]
        year = options['y']
    else:
        year = 'Global'

    if options['t'] is not None:
        TTList = [[options['t']]]
    else:
        tactics = pd.read_csv(str(TTDir / TTFiles[0]))
        techniques = pd.read_csv(str(TTDir / TTFiles[1]))
        TTList = [tactics['ID'].to_list(), techniques['ID'].to_list()]

    res_list = [[], []]
    for idx, list in enumerate(TTList):
        for tt in list:
            tmp = database[(database['Tactics (Enterprise)'].apply(lambda x: is_string_in_text(tt, x)))    |
                           (database['Tactics (ICS)'].apply(lambda x: is_string_in_text(tt, x)))           |
                           (database['Tactics (Mobile)'].apply(lambda x: is_string_in_text(tt, x)))        |
                           (database['Techniques (Enterprise)'].apply(lambda x: is_string_in_text(tt, x))) |
                           (database['Techniques (ICS)'].apply(lambda x: is_string_in_text(tt, x)))        |
                           (database['Techniques (Mobile)'].apply(lambda x: is_string_in_text(tt, x)))]
            res_list[idx].append([tt, year, tmp.shape[0], database.shape[0], tmp.shape[0] / database.shape[0] * 100])
    
    for list in res_list:
        if list:
            res_df = pd.DataFrame(list, columns=['Tactic/Technique', 'Year', 'No. of occurrences', 'Total reports', 'Percentage'])
            res_df = res_df.sort_values('Percentage', ascending=False)
            with pd.option_context('display.max_rows', None, 'display.max_columns', None, 'display.precision', 2):
                print(res_df.to_string(index=False), end='\n\n')

if __name__ == '__main__':
    main()