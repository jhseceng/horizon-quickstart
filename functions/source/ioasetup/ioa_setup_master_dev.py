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

CLOUDTRAIL_NAME = 'cs-horizon-org-trail'

logger = logging.getLogger()
logger.setLevel(logging.INFO)

push_master_stackset = os.environ["CreateStackSet"]
admin_role_arn = os.environ["AdministrationRoleARN"]
exec_role_arn = os.environ["ExecutionRoleARN"]
aws_region = os.environ["AWSRegion"]
ioa_enabled = os.environ["EnableIOA"]
use_existing_cloudtrail = os.environ["UseExistingCloudtrail"]
region_list = os.environ['RegionList'].split(',')


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


def create_self_managed_stackset(stack_set_name, role_descriiption, template_url, admin_role_arn, paramlist,
                                 exec_role_arn, capabilities):
    """ Create SELF-MANAGED StackSet in the Master or Delegated Account """
    CFT = boto3.client('cloudformation')
    logger.info('**** Creating self managed StackSet {} ****'.format(stack_set_name))
    result = {}
    if len(paramlist):
        try:
            result = CFT.create_stack_set(StackSetName=stack_set_name,
                                          Description=role_descriiption,
                                          TemplateURL=template_url,
                                          Parameters=paramlist,
                                          #   AdministrationRoleARN=admin_role_arn,
                                          #   ExecutionRoleName=exec_role_arn,
                                          Capabilities=capabilities)
            return result
        except ClientError as e:
            if e.response['Error']['Code'] == 'NameAlreadyExistsException':
                logger.info("StackSet already exists")
                return
            else:
                logger.error("Unexpected error: %s" % e)
                return


def create_stack_instances(stackset_name, account_id, regions):
    """ Create CRWD Horizon Stackset on the Master Account """
    logger.info('regions type {}'.format(type(regions)))
    client_cft = boto3.client('cloudformation')
    result = {}
    try:
        if regions:
            client_cft.create_stack_instances(
                StackSetName=stackset_name,
                OperationPreferences={
                    'RegionConcurrencyType': 'PARALLEL',
                    'FailureTolerancePercentage': 100,
                    'MaxConcurrentCount': 20,
                },
                Accounts=[account_id],
                Regions=list(regions)
            )
            logger.info('Processed {} Sucessfully'.format(stackset_name))
            return True
        else:
            logger.info('Found no active regions to apply stackset {}'.format(stackset_name))
            return False
    except ClientError as e:
        if e.response['Error']['Code'] == 'NameAlreadyExistsException':
            logger.info("StackSet already exists")
            result['StackSetName'] = 'CRWD-ROLES-CREATION'
        else:
            logger.error("Unexpected error: %s" % e)
            result['Status'] = e
        return False
    except Exception as e:
        logger.error('Unable to create stack :{}, REASON: {}'.format(stackset_name, e))
        return False


def delete_stackset(account, stackset_name):
    cft_client = boto3.client('cloudformation')
    logger.info("***** Deleting StackSet {} *****".format(stackset_name))
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
            counter = 15
            while len(stackset_instances["Summaries"]) > 0 and counter > 0:
                logger.info("Deleting stackset instance from {}, remaining {}, "
                            "sleeping for 10 sec".format(stackset_name, len(stackset_instances["Summaries"])))
                time.sleep(10)
                counter = counter - 1
                stackset_instances = cft_client.list_stack_instances(StackSetName=stackset_name)
            if len(stackset_instances["Summaries"]) > 0:
                cft_client.delete_stack_set(StackSetName=stackset_name)
                logger.info("*** We still have StackSet Instances in {} ****\n **** Trying once more ****".format(
                    stackset_name))
                time.sleep(10)
            else:
                logger.info("**** Deleted all StackSet Instances from StackSet {} ****".format(stackset_name))
            return True

    except ClientError as e:
        if e.response['Error']['Code'] == 'StackSetNotFoundException':
            logger.info("StackSet {} does not exist".format(stackset_name))
            return False
        else:
            logger.error("Unexpected error: %s" % e)
            return False


def create_cloudtrail(s3_bucket_name, region):
    client_ct = boto3.client('cloudtrail', region_name=region)
    logger.info('Creating additional org wide trail {}'.format(s3_bucket_name))
    try:
        client_ct.create_trail(
            Name=CLOUDTRAIL_NAME,
            S3BucketName=s3_bucket_name,
            IsMultiRegionTrail=True,
            IsOrganizationTrail=True,
        )
        client_ct.start_logging(Name=CLOUDTRAIL_NAME)
        return True
    except Exception as e:
        logger.info('Exception creating trail {}'.format(e))
        return False


def delete_cloudtrail(region):
    client_ct = boto3.client('cloudtrail', region_name=region)
    logger.info('Deleting org wide trail {}'.format(CLOUDTRAIL_NAME))
    try:
        client_ct.stop_logging(Name=CLOUDTRAIL_NAME)
        client_ct.delete_trail(
            Name=CLOUDTRAIL_NAME)
        return True
    except Exception as e:
        logger.info('Exception creating trail {}'.format(e))
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
        iam_stackset_param_list = []
        #
        # Build param list from event ResourceProperties
        # IAMStackSetURL, IAMStackSetName and ServiceToken are not input params
        #
        for key in keys:
            keyDict = {}
            if key == 'IAMStackSetURL' or key == 'IAMStackSetName' or key == 'ServiceToken':
                pass
            else:
                keyDict['ParameterKey'] = key
                keyDict['ParameterValue'] = event['ResourceProperties'][key]
                iam_stackset_param_list.append(dict(keyDict))

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
            if ioa_enabled == 'true':
                desc = 'Create EventBridge rule in child accounts in every region to send CloudTrail events to CrowdStrike'
                create_self_managed_stackset(iam_stackset_name, desc, iam_stackset_url, admin_role_arn,
                                             iam_stackset_param_list,
                                             exec_role_arn, clist)
                if push_master_stackset == 'true':
                    logger.info('**** Creating StackInstances in regions {} ****'.format(region_list))
                    stack_op_result = create_stack_instances(iam_stackset_name, account_id, region_list)
                    logger.info('stack_op_result: {}'.format(stack_op_result))
                else:
                    # Skip deployment of Stackset in master
                    logger.info('**** Skipping push of stack instances in regions ****')
                    stack_op_result = True
                #
                # Create org wide trail if required.
                #
                if use_existing_cloudtrail == 'false':
                    cloudtrail_result = create_cloudtrail(ct_bucket, aws_region)
                    logger.info('cloudtrail_result: {}'.format(cloudtrail_result))
                else:
                    # Dont create org wide trail as customer selected true
                    cloudtrail_result = True
                if stack_op_result and cloudtrail_result:
                    cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
                else:
                    logger.info('Failed to apply stackset {}'.format(ioa_stackset_root))
                    cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

        elif event['RequestType'] in ['Update']:
            logger.info('Event = ' + event['RequestType'])

            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
            return

        elif event['RequestType'] in ['Delete']:
            logger.info('Event = ' + event['RequestType'])
            try:
                if ioa_enabled == 'true':
                    delete_stackset([account_id], iam_stackset_name)
                    if use_existing_cloudtrail == 'false':
                        delete_cloudtrail(aws_region)
            except Exception as error:
                logger.info('Error deleting StackSet {}'.format(iam_stackset_name))
                pass
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

    except Exception as e:
        logger.error(e)
        response_data = {"Status": str(e)}
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
        return



