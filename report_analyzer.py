import argparse
import sys
import pandas as pd
import requests
import json
from urllib.parse import urlparse
import re
from pypdf import PdfReader

def is_string_in_text(string, text):
	return True if re.compile(r'\b({0})\b'.format(string)).search(text) is not None else False

out_template = {
    "name" : "",
    "versions" : {
        "attack": "14",
		"navigator": "4.9.4",
		"layer": "4.5"
    },
    "domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": []
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": False,
		"showName": True,
		"showAggregateScores": False,
		"countUnscored": False,
		"expandedSubtechniques": "none"
	},
	"hideDisabled": False,
    "techniques" : [],
    "gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 100
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": False,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": False,
	"selectSubtechniquesWithParent": False,
	"selectVisibleTechniques": False
}

technique_template = {
            "techniqueID": "",
			"color": "",
			"comment": "",
			"enabled": True,
			"metadata": [],
			"links": [],
			"showSubtechniques": True
        	}

def url_valid(url):
	try:
		result = urlparse(url)
		return all([result.scheme, result.netloc])
	except AttributeError:
		return False

def FillInputBuffer(input):
	# Check if input is url
	if url_valid(input):
		#print("Contacting url: " + input)
		return requests.get(input).text
	# If not, check if is txt
	elif bool(re.search(r'\w+(.)txt$', input)):
		#print("Using text file: " + input)
		with open(input) as f:
			s = f.read()
			return s
	# Else check if is PDF
	elif bool(re.search(r'\w+(.)pdf$', input)):
		#print("Using PDF file: " + input)
		reader = PdfReader(input)
		buf = ""
		for page in reader.pages:
			buf += page.extract_text() + "\n"
		return buf
	# Else throw an error
	else:
		print("Error: unknown input")
		sys.exit(1)

def FindTechniques(input, techniques, search_type):
	df = pd.read_csv(techniques)
	#print("---FOUND TECHNIQUES IN SOURCE---")
	found_techniques = []
	for i in range(0, df.shape[0]):
		if search_type == 'id':
			selected_index = i if is_string_in_text(df.iat[i, 0], input) else -1
		elif search_type == 'name':
			selected_index = i if is_string_in_text(df.iat[i, 1], input) else -1
		else:
			selected_index = i if is_string_in_text(df.iat[i, 0], input) or is_string_in_text(df.iat[i, 1], input) else -1

		if selected_index != -1:
			#print("- " + df.iat[selected_index, 1] + " (" + df.iat[selected_index, 0] + ")")
			found_techniques.append(df.iat[selected_index, 0])
	return found_techniques

def BuildLayer(matrix, outname, technique_list, color):
    out = out_template
	
    out['name'] = outname
	
    if matrix == 'm':
        out['domain'] = 'mobile-attack'
        out['filters']['platforms'] = ['Android', 'iOS']
    elif matrix == 'i':
        out['domain'] = 'ics-attack'
        out['filters']['platforms'] = ["None","Windows","Human-Machine Interface","Control Server","Data Historian","Field Controller/RTU/PLC/IED","Input/Output Server","Safety Instrumented System/Protection Relay","Engineering Workstation"]
    else:
        out['domain'] = 'enterprise-attack'
        out['filters']['platforms'] = ["Linux","macOS","Windows","Network","PRE","Containers","Office 365","SaaS","Google Workspace","IaaS","Azure AD"]
    
    technique_dict = technique_template
    for t in technique_list:
        technique_dict['techniqueID'] = t
        technique_dict['color'] = color
        out['techniques'].append(technique_dict.copy())
		
    return out

def main():
    parser = argparse.ArgumentParser(
        prog='report_analyzer',
        description='Reads a report and returns a MITRE ATT&CK Navigator Layer'
	)
    parser.add_argument('-i', nargs='+', help='Input of the program. Can be either an URL or a path to a PDF file or txt file')
    parser.add_argument('-m', choices=['e', 'm', 'i'], default='e', help='Choose the layer matrix from (e)nterprise, (m)obile or (i)cs')
    parser.add_argument('-o', help='Specifies output filename. If not specified the output will be printed on stdout')
    parser.add_argument('-l', help='Specifies layer name. If not specified the layer will be called "layer"')
    parser.add_argument('-c', type=int, nargs=3, choices=range(0, 256), default=[255, 255, 0], metavar='[0-255]', help='Specifies the color of the cells')
    parser.add_argument('-s', choices=['id', 'name', 'both'], default='both', help='Search in the text by technique ID, by name or both')
    parser.add_argument('-t', required=True, help='Specify a CSV file with the techniques to search in the report')
    options = vars(parser.parse_args())
    
    color = "#%02X%02X%02X" % (options['c'][0], options['c'][1], options['c'][2])
    
    techniques = []
    for i in options['i']:
        inbuf = FillInputBuffer(i)
        tmp = FindTechniques(inbuf, options['t'], options['s'])
        techniques = list(set(techniques + tmp))
    
    name = options['l'] if options['l'] is not None else 'layer'
    layer = BuildLayer(options['m'], name, techniques, color)
	
    if options['o'] is not None:
        with open(options['o']+".json", 'w') as f:
            json.dump(layer, f)
    else:
        print(json.dump(layer, sys.stdout))

if __name__ == '__main__':
    main()