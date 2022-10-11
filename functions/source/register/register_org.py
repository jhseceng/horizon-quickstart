import json
import logging
import os
import sys
import boto3
import requests
import time
import base64
from botocore.exceptions import ClientError
from falconpy import CSPMRegistration

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONSTANTS
SUCCESS = "SUCCESS"
FAILED = "FAILED"

secret_store_name = os.environ['SecretName']
secret_store_region = os.environ['SecretRegion']


def get_secret(secret_name, secret_region):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=secret_region
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )


    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']

        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret


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
    OrgId, AccountId = get_master_id()
    aws_region = event['ResourceProperties']['aws_region']
    CSCloud = event['ResourceProperties']['CSCloud']
    try:
        secret_str = get_secret(secret_store_name, secret_store_region)
        if secret_str:
            secrets_dict = json.loads(secret_str)
            FalconClientId = secrets_dict['FalconClientId']
            FalconSecret = secrets_dict['FalconSecret']

            falcon = CSPMRegistration(client_id=FalconClientId,
                                      client_secret=FalconSecret,
                                      base_url=CSCloud
                                      )

        if event['RequestType'] in ['Create']:

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
                response_data = response['body']['resources'][0]
                role_name = response['body']['resources'][0]['iam_role_arn'].rsplit('/')[1]
                response_d = {
                    "iam_role_name": role_name,
                    "external_id": response_data.get('external_id', ''),
                    "aws_cloudtrail_bucket_name": response_data.get('aws_cloudtrail_bucket_name', ''),
                    "eventbus_name": response_data.get('eventbus_name', ''),
                    "aws_eventbus_arn": response_data.get('aws_eventbus_arn', ''),
                    "account_type": response_data.get('account_type', '')
                }
                cfnresponse_send(event, context, SUCCESS, response_d, "CustomResourcePhysicalID")
            else:
                response_d = response['body']
                cfnresponse_send(event, context, FAILED, response_d, "CustomResourcePhysicalID")


        elif event['RequestType'] in ['Update']:
            response_d = {}
            logger.info('Event = ' + event['RequestType'])
            cfnresponse_send(event, context, SUCCESS, response_d, "CustomResourcePhysicalID")

        elif event['RequestType'] in ['Delete']:
            logger.info('Event = ' + event['RequestType'])
            response = falcon.delete_aws_account(organization_ids=OrgId)

            cfnresponse_send(event, context, 'SUCCESS', response['body'], "CustomResourcePhysicalID")

    except Exception as err:  # noqa: E722
        # We can't communicate with the endpoint
        logger.info('Registration Failed {}'.format(err))
        cfnresponse_send(event, context, FAILED, err, "CustomResourcePhysicalID")