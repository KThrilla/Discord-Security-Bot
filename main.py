import discord
import os
import requests
import json
import re
from keep_alive import keep_alive

client = discord.Client()

urlApiLink = 'https://www.virustotal.com/vtapi/v2/url/report'

@client.event
async def on_ready():
  print('We have logged in as {0.user}'.format(client))

@client.event
async def on_message(message):
  #Start of Message Handler
  if message.author == client.user:
    return
  
  ############################URLs###################################
  #Scans Link through VirusTotal API; Returns any detected positive results and prints to console
  try:
    foundLink = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message.content)
    
    params = {'apikey': os.environ['Key'], 'resource': foundLink}
    response = requests.get(urlApiLink, params=params)
    response_json = json.loads(response.content)
    positiveEngineList = []

    print("here1")
    print(response_json)

    for i in response_json["scans"]:
        if(response_json["scans"][i]["detected"] == True):
          positiveEngineList.append(i)

    if(response_json["positives"] > 0):
      await message.channel.send("CAUTION: " + str(response_json["positives"]) + " out of " + str(response_json["total"]) + " vendors flagged this URL as malicious: " + str(positiveEngineList))

    if(response_json["positives"] <= 0):
      await message.channel.send("Safe URL")
    
    return

  except:
    splitLink = foundLink[0].split('/', 3)
    
    params = {'apikey': os.environ['Key'], 'resource': splitLink[2]}
    response = requests.get(urlApiLink, params=params)
    response_json = json.loads(response.content)
    positiveEngineList = []

    for i in response_json["scans"]:
        if(response_json["scans"][i]["detected"] == True):
          positiveEngineList.append(i)

    if(response_json["positives"] > 0):
      await message.channel.send("Searched for '" + splitLink[2] + "'  instead -> " + "CAUTION: " + str(response_json["positives"]) + " out of " + str(response_json["total"]) + " vendors flagged this Website as malicious: " + str(positiveEngineList))

    if(response_json["positives"] <= 0):
      await message.channel.send("Searched for '" + splitLink[2] + "'  instead -> " + "Safe Website")

keep_alive()
client.run(os.environ['BotToken'])

#https://youtube.com/playlist?list=PLEETnX-uPtBXm1KEr_2zQ6K_0hoGH6JJ0