#!/usr/bin/python

import httplib2
import os, sys
import time

from apiclient import discovery
import oauth2client
from oauth2client import client
from oauth2client import tools
from oauth2client.client import flow_from_clientsecrets

import json
from oauth2client.file import Storage


SCOPES = 'https://www.googleapis.com/auth/admin.reports.audit.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Reports API Python Quickstart'

storage = Storage('creds')

credentials = None

def get_credentials():
    credentials = storage.get()
    if credentials is None or credentials.invalid:
        
        flow  = flow_from_clientsecrets('client_secret.json',
                                scope=SCOPES,
                                redirect_uri='urn:ietf:wg:oauth:2.0:oob')

        auth_uri = flow.step1_get_authorize_url()
        print 'goto the following url ' +  auth_uri

        code = raw_input('Enter token:')
        credentials = flow.step2_exchange(code)
        storage.put(credentials)
    return credentials


def register_web_hook(service):
    WEBHOOK_URL = 'https://fabled-ray-104117.appspot.com/push'
    WEBHOOK_ID = "72064707-f035-4192-aeb5-badf61c3b81b"    
    WEBHOOK_EXPIRATION = str(int(round(time.time() * 1000)) + (1000 * 60 * 60 * 6))

    data = { 
     "type": "web_hook", 
     "id": WEBHOOK_ID, 
     "address": WEBHOOK_URL,
     "payload": True, 
     "token": "target=channelToken",
     "expiration": WEBHOOK_EXPIRATION
     }

    results = service.activities().watch(userKey='all', applicationName='admin',
       body=data ).execute()
    print json.dumps(results, indent=4, sort_keys=True)

def query_reports_api(service):

 
    startTime= '2018-04-30T17:11:32.870Z'
    endTime = '2018-04-30T17:11:32.870Z'
    eventName = 'REMOVE_GROUP_MEMBER'
    filters =  'USER_EMAIL==user1@esodemoapp2.com'

    results = service.activities().list(userKey='all', applicationName='admin',
       startTime=startTime,endTime=endTime,eventName=eventName, filters=filters ).execute()

    items = results['items']
    for itm in items:
        i = itm.get('id')
        startTime = i.get('time')
        endTime = i.get('time')
        applicaitonName= i.get('applicationName')
        customerId = i.get('customerId')
        uniqueQualifier = i.get('uniqueQualifier')

        a = itm.get('actor')
        email = a.get('email')

        e_list = itm.get('events')

        for e in e_list:
            etype = e.get('type')
            ename = e.get('name')
            params = e.get('parameters')
            for p in params:
                k = p.get('name')
                v = p.get('value')

                # use these values to verify the push endpoint's payload is real/verified or not, if needed.

                #print startTime
                #print applicaitonName
                #print uniqueQualifier
                #print email
                #print etype
                #print ename
                #print k
                #print v

    print json.dumps(results, indent=4, sort_keys=True)

def main():
    
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('admin', 'reports_v1', http=http)
  
    register_web_hook(service)

    #query_reports_api(service)


if __name__ == '__main__':
    main()
