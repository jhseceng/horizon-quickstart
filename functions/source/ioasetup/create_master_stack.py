#
# Setup IOA in the master account
#
import json
import logging
import os
import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_master_id():
    """ Get the master Id from AWS Organization """
    ORG = boto3.client('organizations')
    try:
        master_id = ORG.list_roots()['Roots'][0]['Arn'].rsplit(':')[4]
        return master_id
    except Exception as e:
        logger.error('This stack runs only on the Master of the AWS Organization: Error {}'.format(e))
        return False


def cfnresponse_send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']
    print(responseUrl)

    responseBody = {'Status': responseStatus,
                    'Reason': 'See the details in CloudWatch Log Stream: ' + context.log_stream_name,
                    'PhysicalResourceId': physicalResourceId or context.log_stream_name, 'StackId': event['StackId'],
                    'RequestId': event['RequestId'], 'LogicalResourceId': event['LogicalResourceId'], 'NoEcho': noEcho,
                    'Data': responseData}

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


def lambda_handler(event, context):
    try:
        logger.info('Got event {}'.format(event))
        logger.info('Context {}'.format(context))

        iam_stackset_url = event['ResourceProperties']["IAMStackSetURL"]
        iam_stackset_name = event['ResourceProperties']["IAMStackSetName"]

        # account_id = get_master_id()
        logger.info('EVENT Received: {}'.format(event))
        keys = event['ResourceProperties'].keys()
        iam_stack_param_list = []
        #
        # Build param list from event ResourceProperties
        # IAMStackSetURL, IAMStackSetName and ServiceToken are not input params
        #
        for key in keys:
            keyDict = {}
            if key == 'IAMStackSetURL' or key == 'IAMStackName' or key == 'ServiceToken':
                pass
            else:
                keyDict['ParameterKey'] = key
                keyDict['ParameterValue'] = event['ResourceProperties'][key]
                iam_stack_param_list.append(dict(keyDict))

        #
        # Get this account ID
        #
        account_id = get_master_id()
        response_data = {}
        clist = ['CAPABILITY_NAMED_IAM']
        if event['RequestType'] in ['Create']:
            #
            # Stackinstances are created in all active regions of root account.
            #
            create_stack(
                StackName=IAMStackName,
                TemplateURL=IAMStackSetURL,
                Parameters=iam_stack_param_list,
                TimeoutInMinutes=5,
                Capabilities=['CAPABILITY_NAMED_IAM']
            )
        elif event['RequestType'] in ['Update']:
            logger.info('Event = ' + event['RequestType'])

            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
            return

        elif event['RequestType'] in ['Delete']:
            logger.info('Event = ' + event['RequestType'])
            try:
                delete_stack(StackName=IAMStackName)
            except Exception as error:
                logger.info('Error deleting StackSet {}'.format(iam_stackset_name))
                pass
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

    except Exception as e:
        logger.error(e)
        response_data = {"Status": str(e)}
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
        return
