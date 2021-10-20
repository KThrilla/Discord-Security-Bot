import requests
import json

url = 'https://www.virustotal.com/vtapi/v2/url/report'
apiKey = 'e5daa1188d0c55c15b8a2c85af79194b4beff84e1435e42256eab79d937f0668'

def linkScan():
  params = {'apikey': apiKey, 'resource': 'https://www.youtube.com/'}
  response = requests.get(url, params=params)
  response_json = json.loads(response.content)
  positiveEngineList = []

  for i in response_json["scans"]:
      if(response_json["scans"][i]["detected"] == True):
        positiveEngineList.append(i)

  if(response_json["positives"] > 0):
    print("CAUTION: " + str(response_json["positive"]) + " out of " + str(response_json["total"]) + " vendors flagged this URL as malicious: " + str(positiveEngineList))
  
  if(response_json["positives"] <= 0):
    print("SAFE: " + str(response_json["positives"]) + " out of " + str(response_json["total"]) + " vendors flagged this URL as malicious")

linkScan()