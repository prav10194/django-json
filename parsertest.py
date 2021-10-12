#!/usr/bin/env python
import json
import argparse

class DjangoParser:
    def __init__(self, input):
        self.input = input
    def parser(self):
        # loading the data
        inputjson = json.loads(self.input.read())

        # updating and removing keys
        inputjson['date'] = inputjson['scan']['scanTime'].split("T")[0]
        del inputjson['scan']['scanTime']
        
        inputjson['description'] = inputjson['name']['fullName']
        del inputjson['name']
        
        inputjson['findings'] = inputjson['scan']['components']
        del inputjson['scan']['components']
        

        for i in range(len(inputjson['findings'])-1,-1,-1):
            if "vulns" not in inputjson['findings'][i]:
                del inputjson['findings'][i]

        for component in inputjson['findings']:
            if "vulns" in component:
                for item in component['vulns']:
                    item['date'] = inputjson['date']
                    item['title'] = inputjson['description'] + " - " + component['name'] + " " + component['version'] + " is vulnerable"
                    if "cvssV2" in item:
                        del item['cvssV2']
                    if "cvss" in item:
                        del item['cvss']
                    if "publishedOn" in item:
                        del item['publishedOn']
                    if "lastModified" in item:
                        del item['lastModified']
                    if "scoreVersion" in item:
                        del item['scoreVersion']
                    if "vulnerabilityType" in item:
                        del item['vulnerabilityType']
                    if "severity" in item:
                        item['severity'] = item['severity'].split("_")[0].capitalize()
                    if "summary" in item:
                        item['description'] = item['summary'] + " " + item['link']
                        del item['summary']
                        del item['link']
                    if "cvssV3" in item:
                        item['cvssV3'] = item['cvssV3']['vector']
                    if "fixedBy" in item:
                        del item['fixedBy']
            if "layerIndex" in component:
                del component['layerIndex']
            if "topCvss" in component:            
                del component['topCvss']
            if "riskScore" in component:
                del component['riskScore']
            if "name" in component:
                del component['name']
            if "version" in component:
                del component['version']

        inputjson['newFindings'] = []

        for component in inputjson['findings']:
            for item in component['vulns']: 
                inputjson['newFindings'].append(item)

        # remove and update 'findings' to 'newFindings'
        del inputjson['findings']
        inputjson['findings'] = inputjson['newFindings']
        del inputjson['newFindings']
        

        # removing the extra keys
        del inputjson['metadata']
        del inputjson['scan']
        del inputjson['id']
        del inputjson['components']
        del inputjson['cves']
        del inputjson['fixableCves']
        del inputjson['lastUpdated']
        del inputjson['riskScore']
        del inputjson['topCvss']
        del inputjson['date']
        del inputjson['description']

        return inputjson

if __name__ == "__main__":

    # added code for command line arguments
    # refer to them by python3 parsertest.py -h
    parser = argparse.ArgumentParser(usage='python3 %(prog)s -i <inputfile.json> -o <outputfile.json>', description='Arguments for Django parser.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--inputfile', help='provide path for the input file to be parsed')
    parser.add_argument('-o', '--outputfile', default='scanoutputjson.json', help='provide path for the output file')
    args = parser.parse_args()

    # reading the input json
    parserObj = DjangoParser(open(args.inputfile, "r")) 

    # calling and retrieving the output parsed json
    outputjson = json.dumps(parserObj.parser(), indent = 4)

    # saving the parsed json in the outputfile
    with open(args.outputfile, "w") as outfile:
        outfile.write(outputjson)
