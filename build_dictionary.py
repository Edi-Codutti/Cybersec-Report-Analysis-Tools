"""
MITRE License
-------------
The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, 
development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

"© 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
"""

import requests
from stix2 import MemoryStore, Filter
import pandas as pd
import argparse
import os
from pathlib import Path

dirname = Path("TTLists")

mitre_domains = ['enterprise-attack', 'mobile-attack', 'ics-attack']

def remove_revoked(stix_objects):
    return list(
        filter(
            lambda x: x.get("revoked", False) is False,
            stix_objects
        )
    )

def get_data_from_branch(domain):
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
    print("Contacting:", url)
    stix_json = requests.get(url).json()
    return MemoryStore(stix_data=stix_json["objects"])

def get_techniques(src:MemoryStore):
    return src.query([Filter('type', '=', 'attack-pattern')])

def get_tactics(src):
    tactics = {}
    matrix = src.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])
    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(src.get(tactic_id))

    return tactics

def build_dictionary(domain:str, what:str):
    src = get_data_from_branch(domain)
    d_name = domain.split(sep='-')[0]

    if what == 't' or what == 'a':
        print("    Generating corresponding techniques file...")
        technique_list = []
        subtechniques = get_techniques(src)
        subtechniques = remove_revoked(subtechniques)
        for s in subtechniques:
            name = s.get('name')
            id = s.get('external_references')[0]['external_id']
            technique_list.append([id, name])
        t_df = pd.DataFrame(technique_list, columns=['ID', 'Name'])
        filename = dirname / ''.join([d_name, "_techniques.csv"])
        os.makedirs(dirname, exist_ok=True)
        t_df.to_csv(filename, index=False)

    if what == 'T' or what == 'a':
        print("    Generating corresponding tactics file...")
        tactic_list = []
        tactics = get_tactics(src)
        for key in tactics.keys():
            subtactics = remove_revoked(tactics[key])
            for t in subtactics:
                name = t['name']
                id = t['external_references'][0]['external_id']
                tactic_list.append([id, name])
        T_df = pd.DataFrame(tactic_list, columns=['ID', 'Name'])
        filename = dirname / ''.join([d_name, "_tactics.csv"])
        os.makedirs(dirname, exist_ok=True)
        T_df.to_csv(filename, index=False)

def main():
    parser = argparse.ArgumentParser(
        prog='build_dictionary',
        description='Builds a dictionary of techniques or tactics to be used with the report analyzer'
    )
    parser.add_argument('-m', choices=['e', 'm', 'i', 'a'], default='a', help='Choose a matrix type among (e)nterprise, (m)obile, (i)cs or (a)ll')
    parser.add_argument('-g', choices=['t', 'T', 'a'], default='a', help='Choose wether to generate dictionaries for techniques (t), tactics (T) or (a)ll')
    options = vars(parser.parse_args())
    if options['d'] == 'a':
        for domain in mitre_domains:
            build_dictionary(domain, options['g'])
        compendium = pd.concat([
            pd.read_csv(str(dirname / "enterprise_techniques.csv")),
            pd.read_csv(str(dirname / "mobile_techniques.csv")),
            pd.read_csv(str(dirname / "ics_techniques.csv")),
            ]).drop_duplicates().reset_index(drop=True)
        compendium.to_csv(str(dirname / "compendium_techniques.csv"), index=False)
        compendium = pd.concat([
            pd.read_csv(str(dirname / "enterprise_tactics.csv")),
            pd.read_csv(str(dirname / "mobile_tactics.csv")),
            pd.read_csv(str(dirname / "ics_tactics.csv")),
            ]).drop_duplicates().reset_index(drop=True)
        compendium.to_csv(str(dirname / "compendium_tactics.csv"), index=False)
    elif options['m'] == 'e':
        build_dictionary(mitre_domains[0], options['g'])
    elif options['m'] == 'm':
        build_dictionary(mitre_domains[1], options['g'])
    elif options['m'] == 'i':
        build_dictionary(mitre_domains[2], options['g'])

if __name__ == '__main__':
    main()