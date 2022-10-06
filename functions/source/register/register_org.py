import json
import logging
import os
import sys
import boto3
import requests
import time
from falconpy import CSPMRegistration

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONSTANTS
SUCCESS = "SUCCESS"
FAILED = "FAILED"


def cfnresponse_send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']
    print(responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: '
    responseBody['PhysicalResourceId'] = physicalResourceId
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    print("Response body:\n" + json_responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))

def get_master_id():
    """ Get the master Id from AWS Organization - Only on master"""
    masterID = ''
    ORG = boto3.client('organizations')
    try:
        orgIDstr = ORG.list_roots()['Roots'][0]['Arn'].rsplit('/')[1]
        masterID = ORG.list_roots()['Roots'][0]['Arn'].rsplit(':')[4]
        return orgIDstr, masterID
    except Exception as e:
        logger.error('This stack runs only on the Master of the AWS Organization')
        return False




def lambda_handler(event, context):
    logger.info('Got event {}'.format(event))
    logger.info('Context {}'.format(context))
    #  Exampe response to post request
    # resources = [
    #     {
    #         "CreatedAt": "2021-07-01T19:47:32.787Z",
    #         "DeletedAt": "2021-07-01T19:47:32.787Z",
    #         "ID": 0,
    #         "UpdatedAt": "2021-07-01T19:47:32.787Z",
    #         "account_id": "string",
    #         "aws_cloudtrail_bucket_name": "string",
    #         "aws_cloudtrail_region": "string",
    #         "aws_permissions_status": [
    #             {
    #                 "name": "string",
    #                 "status": "string"
    #             }
    #         ],
    #         "cid": "string",
    #         "cloudformation_url": "string",
    #         "eventbus_name": "string",
    #         "external_id": "string",
    #         "iam_role_arn": "string",
    #         "intermediate_role_arn": "string",
    #         "is_master": true,
    #         "organization_id": "string",
    #         "status": "string"
    #     }
    #
    # ]
    CFT = boto3.client('cloudformation')
    OrgId, AccountId = get_master_id()
    aws_region = event['ResourceProperties']['aws_region']
    CSCloud = event['ResourceProperties']['CSCloud']
    FalconClientId = event['ResourceProperties']['FalconClientId']
    FalconSecret = event['ResourceProperties']['FalconSecret']

    falcon = CSPMRegistration(client_id=FalconClientId,
                              client_secret=FalconSecret,
                              base_url=CSCloud
                              )
    if event['RequestType'] in ['Create']:
        # Format post message
        try:
            # Execute the command by calling the named function
            response_data = {}
            logger.info('Event = {}'.format(event))
            response = falcon.create_aws_account(account_id=AccountId,
                                                 organization_id=OrgId,
                                                 cloudtrail_region=aws_region,
                                                 parameters={"account_type": "commercial"})
            if response['status_code'] == 400:
                #
                # We have an error
                #
                error = response['body']['errors'][0]['message']
                logger.info('Account Registration Failed with reason....{}'.format(error))
                cfnresponse_send(event, context, FAILED, error, response['body']['errors'][0]['message'])
            elif response['status_code'] == 201:
                response_data= response['body']['resources'][0]
                role_name = response['body']['resources'][0]['iam_role_arn'].rsplit('/')[1]
                response_d = {
                    "iam_role_name": role_name,
                    "external_id": response_data.get('external_id',''),
                    "aws_cloudtrail_bucket_name": response_data.get('aws_cloudtrail_bucket_name',''),
                    "eventbus_name": response_data.get('eventbus_name',''),
                    "aws_eventbus_arn": response_data.get('aws_eventbus_arn', ''),
                    "account_type": response_data.get('account_type', '')
                }
                cfnresponse_send(event, context, SUCCESS, response_d,"CustomResourcePhysicalID")
            else:
                response_d = response['body']
                cfnresponse_send(event, context, FAILED, response_d,"CustomResourcePhysicalID")
        except Exception as err:  # noqa: E722
            # We can't communicate with the endpoint
            logger.info('Registration Failed {}'.format(err))
            cfnresponse_send(event, context, FAILED, err, "CustomResourcePhysicalID")

    elif event['RequestType'] in ['Update']:
        response_d = {}
        logger.info('Event = ' + event['RequestType'])
        cfnresponse_send(event, context, SUCCESS, response_d, "CustomResourcePhysicalID")

    elif event['RequestType'] in ['Delete']:
        logger.info('Event = ' + event['RequestType'])
        response = falcon.delete_aws_account(organization_ids=OrgId)
        CFT.delete_stack(
            StackName="CrowdStrike-CSPM-Integration-EB")
        CFT.delete_stack(
            StackName="CrowdStrike-CSPM-Root-EB")
        CFT.delete_stack(
            StackName="CrowdStrike-CSPM-Integration")

        cfnresponse_send(event, context, 'SUCCESS', response['body'], "CustomResourcePhysicalID")



