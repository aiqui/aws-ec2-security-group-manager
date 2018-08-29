#!/usr/bin/env python

import boto3
import botocore
import re
import argparse
import unittest
import getpass
import sys
from pprint import pprint

class Ec2Manager:

    # Class parameters
    oClient         = None
    aSecurityGroups = None
    
    def errorMsg (self, sMsg):
        print "Error: " + sMsg
        sys.exit(-1)

    def verify (self, sMsg, sDefault = ""):
        sReply = self.getResponse(sMsg + " ")
        if re.search('\w', sDefault) and sReply == "":
            sReply = sDefault
        return sReply == "yes" or sReply == "y"

    def strToInt (self, s):
        try:
            i = int(s)
        except ValueError as e:
            i = -1
        return i

    def getResponse (self, sPrompt, bValidStr = False, bHidden = False):
        try:
            sInput = ""
            while re.search('\w', sInput) == None:
                if bHidden:
                    sInput = getpass.getpass(sPrompt)
                else:
                    sInput = raw_input(sPrompt)
                if re.search('\w', sInput) != None:
                    return sInput.strip()
                if bValidStr == False:
                    return '';
        except KeyboardInterrupt:
            print
            print "Exiting..."
            sys.exit(-1)

    def isAwsSuccessRequest (self, aResponse):
        """Determine if a response from AWS is successful"""
        return ('ResponseMetadata' in aResponse and
                'HTTPStatusCode' in aResponse['ResponseMetadata'] and
                aResponse['ResponseMetadata']['HTTPStatusCode'] in [ 200 ])

    def getClient (self, sAwsId):
        """Get the Boto EC2 client"""
        while self.oClient == None:
            try: 
                if sAwsId == None:
                    sAwsId  = self.getResponse("AWS account ID? ", True)
                sAwsKey = self.getResponse("AWS account access key? ", True, True)
                self.oClient = boto3.client('ec2', aws_access_key_id = sAwsId, aws_secret_access_key = sAwsKey)
                aAllGroups = self.oClient.describe_security_groups()
                self.aSecurityGroups = {}
                for aGroup in aAllGroups["SecurityGroups"]:
                    self.aSecurityGroups[aGroup['GroupId']] = aGroup
            except botocore.exceptions.ClientError as e:
                print "Invalid AWS credentials, please try again..."
                print
                self.oClient = None
        return self.oClient
        
    def showIpPermissions (self, sGroupId):
        """Show the IP ranges for a security group"""
        aResponse = self.oClient.describe_security_groups(GroupIds=[sGroupId])
        self.printPermissionsTable(aResponse['SecurityGroups'][0])
        

    def printPermissionsTable (self, aGroup):
        """Print the incoming permissions table"""
        print "Incoming IP Permissions:"
        print "      %-4s  %-8s %-19s %s" % ('Port', 'Protocol', 'IP range', 'Description')
        bNoRow = True
        iIndex = 0
        aRanges = []
        for aPermit in aGroup['IpPermissions']:
            if 'FromPort' in aPermit:
                for aRange in aPermit['IpRanges']:
                    iIndex = iIndex + 1
                    sDesc = ''
                    if 'Description' in aRange:
                        sDesc = aRange['Description']
                    print " %2d.  %4s  %-8s %-19s %s" % (iIndex, aPermit['FromPort'], aPermit['IpProtocol'],
                                                         aRange['CidrIp'], sDesc)
                    aRanges.append({'ip':       aRange['CidrIp'],
                                    'port':     aPermit['FromPort'],
                                    'protocol': aPermit['IpProtocol']})
        if len(aRanges) == 0:
            print "-- none defined --"
        print
        return aRanges
        
    def validIp4 (self, sIp):
        return re.search('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$', sIp) != None

    def addIpPermissions (self, sGroupId):
        """Add to the IP permissions to a security group"""
        print "Adding permissions to %s - %s" % (sGroupId,  self.aSecurityGroups[sGroupId]['Description'])

        while True:
            print
            aResponse = self.oClient.describe_security_groups(GroupIds=[sGroupId])
            self.printPermissionsTable(aResponse['SecurityGroups'][0])
            iPort = 0
            while iPort < 1:
                iPort = self.strToInt(self.getResponse("Port number: ", True))

            sProtocol = self.getResponse("Protocol: (tcp) ")
            if re.search('\w', sProtocol) == None:
                sProtocol = 'tcp'

            sIpRange = ''
            while True:
                sIpRange = self.getResponse("CIDR IP range: ")
                if self.validIp4(sIpRange):
                    break
                print
                print "Invalid CIDR IP range, please try again..."
                print

            sDesc = self.getResponse("Description: ", True)

            if self.getResponse("Add %s permissions to port %d for range %s? (yes) " %
                                (sProtocol, iPort, sIpRange)) in ['', 'yes', 'y']:
                aResponse = self.oClient.authorize_security_group_ingress(
                    GroupId = sGroupId,
                    IpPermissions = [
                        { 'FromPort': iPort,
                          'ToPort': iPort,
                          'IpProtocol': sProtocol,
                          'IpRanges': [{ 'CidrIp': sIpRange, 'Description': sDesc }] }
                    ])
                # pprint(aResponse)
                if self.isAwsSuccessRequest(aResponse):
                    print "Permission successfully added"
                else:
                    print "Permission failed to add"
                    
                print

            if self.getResponse("Add another IP permission? (yes) ") not in ['', 'yes', 'y']:
                break
            

    def removeIpPermissions (self, sGroupId):
        """Remove IP permissions from a security group"""
        while True:
            print
            aResponse = self.oClient.describe_security_groups(GroupIds=[sGroupId])
            aRanges = self.printPermissionsTable(aResponse['SecurityGroups'][0])
            sIndex = self.getResponse("Which permission to delete? (exit) ")
            print
            if sIndex == '':
                return
            iIndex = self.strToInt(sIndex)
            if iIndex > 0 and iIndex <= len(aRanges):
                oRange = aRanges[iIndex - 1]
                if self.getResponse("Remove permission for IP: %s port: %s protocol: %s? (yes) " %
                                (oRange['ip'], oRange['port'], oRange['protocol'])) in ['', 'yes', 'y']:
                    aResponse = self.oClient.revoke_security_group_ingress(
                        GroupId = sGroupId,
                        IpPermissions = [
                            { 'FromPort': oRange['port'],
                              'ToPort': oRange['port'],
                              'IpProtocol': oRange['protocol'],
                              'IpRanges': [{ 'CidrIp': oRange['ip'] }] }
                        ])
                    if self.isAwsSuccessRequest(aResponse):
                        print "Permission successfully removed"
                    else:
                        print "Permission failed to remove"
            

    def strLimit (self, sValue, iLength):
        if len(sValue) > iLength:
            return sValue[0:(iLength - 3)] + '...'
        else:
            return sValue

    def getGroupId (self):
        """Get the security group ID"""
        iIndex = 0
        while iIndex < 1 or iIndex > len(self.aSecurityGroups):
            print
            print "      %-12s %-20s %s" % ('Group ID', 'Group Name', 'Description')
            n = 0
            for sId, aGroup in self.aSecurityGroups.items():
                n = n + 1
                sName = self.strLimit(aGroup['GroupName'], 20)
                sDesc = self.strLimit(aGroup['Description'], 60)
                print "  %2d: %-12s %-20s %s" % (n, sId, sName, sDesc)
            print "   x: exit"
            print
            sResponse = self.getResponse("Select a security group (1 to %d): " % n)
            if sResponse == 'x':
                sys.exit(0)
            iIndex = self.strToInt(sResponse)
        return list(self.aSecurityGroups)[iIndex - 1]

    def groupAction (self, sGroupId):
        """All major actions for a group"""
        aGroup = self.aSecurityGroups[sGroupId]
        while True:
            print "Action for security group %s - %s: " % (sGroupId, aGroup['Description'])
            print "  1.  show incoming IP permissions"
            print "  2.  add to the incoming IP ranges"
            print "  3.  remove from the IP ranges"
            sResponse = self.getResponse("Action: (exit) ")
            print
            if sResponse == '1':
                self.showIpPermissions(sGroupId)
            elif sResponse == '2':
                self.addIpPermissions(sGroupId)
            elif sResponse == '3':
                self.removeIpPermissions(sGroupId)
            else:
                return

    def main (self, sAwsId):
        self.getClient(sAwsId)
        while True:
            sGroupId = self.getGroupId()
            self.groupAction(sGroupId)
            
            
if __name__ == "__main__":
    oParser = argparse.ArgumentParser(description='Security Group Manager')
    oParser.add_argument('--id', nargs=1, metavar='ID', help='AWS security credential ID')
    oArgs = oParser.parse_args()
    sAwsId = None
    if oArgs.id:
        sAwsId = oArgs.id[0]

    oManager = Ec2Manager()
    oManager.main(sAwsId)
