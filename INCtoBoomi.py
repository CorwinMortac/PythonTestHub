###INCtoBoomiV2###

import requests
import re
import time
import json, hashlib
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
from datetime import datetime

from ipaascore.BaseStep import BaseStep
from ipaascore import parameter_types

check_scheme = lambda x: x if x.startswith("http") else "http://{}".format(x)

API_URL = "{}/api/event/{}"

class IncidentToBoomiTesting(BaseStep):
    def __init__(self):


        self.new_step_parameter(
            name="boomi_url",
            description="Boomi URL",
            required=False,
            param_type=parameter_types.StringParameterShort()
        )

        self.new_step_parameter(
             name="boomi_token",
             description="Boomi bearer token",
             required=False,
             param_type=parameter_types.StringParameterLong()
        )
        self.new_step_parameter(
            name="sl1_hostname",
            description="SL1 CDB hostname",
            required=False,
            param_type=parameter_types.StringParameterShort()
        )

        self.new_step_parameter(
             name="sl1_username",
             description="SL1 CDB Username",
             required=False,
             param_type=parameter_types.StringParameterShort()
        )

        self.new_step_parameter(
             name="sl1_password",
             description="SL1 CDB Password",
             required=False,
             param_type=parameter_types.StringParameterLong()
        )
        self.new_step_parameter(
            name="source",
            description="Source",
            required=False,
            param_type=parameter_types.StringParameterShort()
        )

        self.new_step_parameter(
             name="event_type",
             description="Event Type",
             required=False,
             param_type=parameter_types.StringParameterShort()
        )

        self.new_step_parameter(
             name="event_details",
             description="Event details ",
             required=True,
             param_type=parameter_types.JSONParameter()
        )

    def init_run(self):
        self.boomi_url = check_scheme(self.get_parameter("boomi_url"))
        self.boomi_token = self.get_parameter("boomi_token")
        self.source = self.get_parameter("source")
        self.sl1_hostname = check_scheme(self.get_parameter("sl1_hostname"))
        self.sl1_username = self.get_parameter("sl1_username")
        self.sl1_password = self.get_parameter("sl1_password")
        self.event_type = self.get_parameter("event_type")
        self.event_details = self.get_parameter("event_details")
        self.logger.info("event_details: {}".format(str(self.event_details)))

    def CreateIncident(self):

        event_description = "[{}] {}: {}".format(
            self.event_details['%S'],
            self.event_details['%_event_policy_name'],
            self.event_details['%M']
        )

        self.logger.flow(event_description)

        payload = {
            "Status__c":                   "Active",
            "System__c":                   self.source,
            "Details__c":                  event_description,
            "Device_Id__c":                self.event_details['%x'],
            "SF_AccountID":                self.event_details['%C'],
            "Event_Id__c":                 self.event_details['%e'],
            "Type__c":                     self.event_type,
            "Urgency__c":                  self.event_details['%S'],
            "Informational__c":            None,
            "Performance_Impacted__c":     None,
            "Root_Cause__c":               None,
            "Timestamp_of_Event_UTC__c":   datetime.strptime(self.event_details['%D'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S.000Z")
        }

        self.logger.flow("Payload: {}".format(str(payload)))

        headers = {
            "Authorization": f"Bearer {self.boomi_token}",
            "Content-Type": "application/json"
        }

        url = f"{self.boomi_url}"

        apiCall = requests.post(url, json=payload, headers=headers, timeout=60)

        return apiCall

    def ResolveIncident(self):
        payload = {
            "Status__c":                   "Inactive",
            "System__c":                   self.source,
            "Device_Id__c":                self.event_details['%x'],
            "SF_AccountID":                self.event_details['%C'],
            "Event_Id__c":                 self.event_details['%e'],
            "Type__c":                     self.event_type,
            "Timestamp_of_Event_UTC__c":   datetime.strptime(self.event_details['%d'], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S.000Z")
        }

        self.logger.flow("Payload: {}".format(str(payload)))

        headers = {
            "Authorization": f"Bearer {self.boomi_token}",
            "Content-Type": "application/json"
        }

        url = f"{self.boomi_url}"

        apiCall = requests.post(url, json=payload, headers=headers, timeout=60)

        return apiCall    

    def execute(self):
        self.init_run()
        if not self.event_details['%4']:
            response = self.CreateIncident()
        else:
            response = self.ResolveIncident()

        if response.status_code == 200 or response.status_code == 500:
            self.logger.info("Data transmitted successfully")
        else:
            self.logger.error(f"Failed to transmit data. Status code: {response.status_code}, Error message: {response.text}")
