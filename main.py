import discord
import os
import requests
import json
import re
from keep_alive import keep_alive

client = discord.Client()

urlApiLink = 'https://www.virustotal.com/vtapi/v2/url/report'

def linkFound(message):
  container = message.rsplit(" ")

  for word in container:
    if word.startswith("http") or word.startswith("www"):
      return True
  
  return False


def linkString(message):
  container = message.rsplit(" ")

  for word in container:
    if word.startswith("http") :
      wordList = word.split("/")
      return wordList[2]
    elif word.startswith("www"):
      wordList = word.split("/")
      return wordList[0]

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
  if(linkFound(message.content)):
    try:
      link = linkString(message.content)
      
      params = {'apikey': os.environ['Key'], 'resource': link}
      response = requests.get(urlApiLink, params=params)
      response_json = json.loads(response.content)
      positiveEngineList = []

      for i in response_json["scans"]:
          if(response_json["scans"][i]["detected"] == True):
            positiveEngineList.append(i)

      if(response_json["positives"] > 0):
        await message.channel.send("CAUTION: " + str(response_json["positives"]) + " out of " + str(response_json["total"]) + " vendors flagged this URL as malicious: " + str(positiveEngineList))

      if(response_json["positives"] <= 0):
        await message.channel.send("Safe URL")
      
      return

    except:
      pass

keep_alive()
client.run(os.environ['BotToken'])