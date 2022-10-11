#
# Setup IOA in the master account
#
import json
import logging
import os
import time
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


def get_regions():
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions


def create_service_managed_stacket(stack_set_name, role_descriiption, template_url, param_list, capabilities):
    CFT = boto3.client('cloudformation')
    ''''''
    try:
        result = CFT.create_stack_set(StackSetName=stack_set_name,
                                      Description=role_descriiption,
                                      TemplateURL=template_url,
                                      Parameters=param_list,
                                      PermissionModel='SERVICE_MANAGED',
                                      AutoDeployment={
                                          'Enabled': True,
                                          'RetainStacksOnAccountRemoval': False
                                      },
                                      Capabilities=capabilities)
        return result
    except ClientError as e:
        if e.response['Error']['Code'] == 'NameAlreadyExistsException':
            logger.info("StackSet already exists")
            return
        else:
            logger.error("Unexpected error: %s" % e)
            return


def delete_stackset(account, stackset_name):
    cft_client = boto3.client('cloudformation')
    try:
        stackset_result = cft_client.describe_stack_set(StackSetName=stackset_name)
        if stackset_result and 'StackSet' in stackset_result:
            stackset_instances = cft_client.list_stack_instances(StackSetName=stackset_name)
            while 'NextToken' in stackset_instances:
                stackinstancesnexttoken = stackset_instances['NextToken']
                morestackinstances = cft_client.list_stack_instances(NextToken=stackinstancesnexttoken)
                stackset_instances["Summaries"].extend(morestackinstances["Summaries"])
            if len(stackset_instances["Summaries"]) > 0:
                stack_instance_regions = list(set(x["Region"] for x in stackset_instances["Summaries"]))
                cft_client.delete_stack_instances(
                    StackSetName=stackset_name,
                    Accounts=account,
                    Regions=stack_instance_regions,
                    OperationPreferences={'MaxConcurrentCount': 20, 'RegionConcurrencyType': 'PARALLEL'},
                    RetainStacks=False
                )
            stackset_instances = cft_client.list_stack_instances(StackSetName=stackset_name)
            counter = 10
            while len(stackset_instances["Summaries"]) > 0 and counter > 0:
                logger.info("Deleting stackset instance from {}, remaining {}, "
                            "sleeping for 10 sec".format(stackset_name, len(stackset_instances["Summaries"])))
                time.sleep(10)
                counter = counter - 1
                stackset_instances = cft_client.list_stack_instances(StackSetName=stackset_name)
            if counter > 0:
                cft_client.delete_stack_set(StackSetName=stackset_name)
                logger.info("StackSet {} deleted".format(stackset_name))
            else:
                logger.info("StackSet {} still has stackset instance, skipping".format(stackset_name))
            return True

    except ClientError as e:
        if e.response['Error']['Code'] == 'StackSetNotFoundException':
            logger.info("StackSet {} does not exist".format(stackset_name))
            return False
        else:
            logger.error("Unexpected error: %s" % e)
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

        
        logger.info('EVENT Received: {}'.format(event))
        keys = event['ResourceProperties'].keys()
        iam_stackset_param_list = []
        for key in keys:
            keyDict = {}
            if key == 'IAMStackSetURL' or key == 'IAMStackSetName' or key == 'ServiceToken':
                pass
            else:
                keyDict['ParameterKey'] = key
                keyDict['ParameterValue'] = event['ResourceProperties'][key]
                iam_stackset_param_list.append(dict(keyDict))

        account_id = get_master_id()
        # logger.info('EVENT Received: {}'.format(event))
        response_data = {}
        if event['RequestType'] in ['Create']:
            #
            # Stackinstances are created in all active regions of root account.
            #
            desc = 'Create EventBridge rule in child accounts in every region to send CloudTrail events to CrowdStrike'
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

            clist = ['CAPABILITY_NAMED_IAM']
            try:
                # logger.info('ParamList {}'.format(clist))
                resp = create_service_managed_stacket(iam_stackset_name, desc, iam_stackset_url,
                                                      iam_stackset_param_list, clist)
                logger.info('Create StackSet Response {}'.format(resp))
            except Exception as error:
                logger.info('Got error {}'.format(error))


        elif event['RequestType'] in ['Update']:
            logger.info('Event = ' + event['RequestType'])

            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
            return

        elif event['RequestType'] in ['Delete']:
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
            logger.info('Event = ' + event['RequestType'])
            delete_stackset([account_id], iam_stackset_name)

    except Exception as e:
        logger.error(e)
        response_data = {"Status": str(e)}
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
        return
