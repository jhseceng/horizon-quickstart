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

cloudformation_client = boto3.client('cloudformation')

CLOUDTRAIL_NAME = 'cs-horizon-org-trail'
RETRIES = 12
SLEEP = 10

logger = logging.getLogger()
logger.setLevel(logging.INFO)

admin_role_arn = os.environ['AdministrationRoleARN']
exec_role_arn = os.environ['ExecutionRoleARN']
aws_region = os.environ['AWSRegion']
account_id = os.environ['AWSAccount']

class OperationFailedError(Exception):
    pass

def wait_for_stack_operation(stackset_name, operation_id, operation_name):
    """
    Wait for operation to complete.
    """
    logger.error("Waiting for stack instance removal from {}".format(stackset_name))

    for retry_count in range(RETRIES):
        current_status = "FAILED_TO_FETCH"
        try:
            response = cloudformation_client.describe_stack_set_operation(
                StackSetName=stackset_name, OperationId=operation_id)
            current_status = response.get('StackSetOperation').get('Status')
        except Exception as e:
            logger.error("Could not get operation details")

        logger.info("Current operation: '{}' Status: {}".format(operation_name, current_status))

        if current_status == "SUCCEEDED":
            return
        elif current_status == "FAILED":
            raise OperationFailedError("Operation {} failed to complete!".format(operation_name, ))

        logger.info("Sleeping for {} seconds".format(SLEEP))

        time.sleep(SLEEP)


def create_self_managed_stackset(stackset_name, role_descriiption, template_url, admin_role_arn, paramlist,
                                 exec_role_arn, capabilities):
    """ Create SELF-MANAGED StackSet in the Master or Delegated Account """

    logger.info('**** Creating self managed StackSet {} ****'.format(stackset_name))
    result = {}
    if len(paramlist):
        try:
            result = cloudformation_client.create_stack_set(StackSetName=stackset_name,
                                                            Description=role_descriiption,
                                                            TemplateURL=template_url,
                                                            Parameters=paramlist,
                                                            AdministrationRoleARN=admin_role_arn,
                                                            ExecutionRoleName=exec_role_arn,
                                                            Capabilities=capabilities)
            return result
        except ClientError as e:
            if e.response['Error']['Code'] == 'NameAlreadyExistsException':
                logger.info("StackSet already exists")
                return
            else:
                logger.error("Unexpected error: %s" % e)
                return


def delete_stack_instances(account,stackset_name):
    stackset_instances = cloudformation_client.list_stack_instances(StackSetName=stackset_name)

    if len(stackset_instances['Summaries']) > 0:
        stack_instance_regions = list(set(x['Region'] for x in stackset_instances['Summaries']))
        logger.info("**** Deleting stack instances in regions {} ****".format(stack_instance_regions))
        try:
            response = cloudformation_client.delete_stack_instances(
                StackSetName=stackset_name,
                Accounts=account,
                Regions=stack_instance_regions,
                OperationPreferences={'MaxConcurrentCount': 20, 'RegionConcurrencyType': 'PARALLEL'},
                RetainStacks=False
            )
            logger.info('Response to delete stack request {}'.format(response))
            wait_for_stack_operation(stackset_name, response.get('OperationId'), "delete_stack_instances")
            return True
        except Exception as error:
            logger.info("Stack instance deletion failed with error: {error}.".format(error))
            return


def delete_stackset(account, stackset_name):

    try:
        stackset_result = cloudformation_client.describe_stack_set(StackSetName=stackset_name)
        if stackset_result and 'StackSet' in stackset_result:
            logger.info("***** Deleting StackSet {} *****".format(stackset_name))
            stackset_instances = cloudformation_client.list_stack_instances(StackSetName=stackset_name)
            if len(stackset_instances['Summaries']) > 0:
                logger.info("Stackset Instances {}".format(stackset_instances['Summaries']))
                delete_stack_instances(account, stackset_name)
            else:
                logger.info("**** Deleted all StackSet Instances from StackSet {} ****".format(stackset_name))
            cloudformation_client.delete_stack_set(StackSetName=stackset_name)
            return True
    except ClientError as error:
        if error.response['Error']['Code'] == 'StackSetNotFoundException':
            logger.info("***** StackSet {} does not exist - Skipping deletion *****".format(stackset_name))
            return False
        else:
            logger.error("Unexpected error: {}".format(error))
            return False


def create_cloudtrail(s3_bucket_name, region):
    client_ct = boto3.client('cloudtrail', region_name=region)
    logger.info('**** Creating additional org wide trail {} '.format(CLOUDTRAIL_NAME))
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
    logger.info('**** Deleting org wide trail {} ****'.format(CLOUDTRAIL_NAME))
    try:
        client_ct.stop_logging(Name=CLOUDTRAIL_NAME)
        client_ct.delete_trail(
            Name=CLOUDTRAIL_NAME)
        return True
    except Exception as e:
        logger.info('Exception deleting trail {}'.format(e))
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


def trail_exists():
    #
    # Check if we have an existing trail
    #
    ct_client = boto3.client('cloudtrail')
    # Check that we have some trails
    trail_list = ct_client.list_trails()['Trails']
    # Check that we have some trails
    if len(trail_list) > 0:
        for trail in trail_list:
            if trail['Name'] == CLOUDTRAIL_NAME:
                logger.info('**** CloudTrail {} exists already ****'.format(CLOUDTRAIL_NAME))
                return True
            else:
                logger.info('**** CloudTrail {} does not exist ****'.format(CLOUDTRAIL_NAME))
    return False


def lambda_handler(event, context):
    try:
        logger.info('Got event {}'.format(event))
        logger.info('Context {}'.format(context))
        #
        # Extract the values required to create the stacks
        #
        iam_stackset_url = event['ResourceProperties']['IAMStackSetURL']
        iam_stackset_name = event['ResourceProperties']['IAMStackSetName']
        ct_bucket = event['ResourceProperties']['CloudTrailBucket']
        ioa_enabled = event['ResourceProperties']['EnableIOA']
        use_existing_cloudtrail = event['ResourceProperties']['UseExistingCloudtrail']

        logger.info('EVENT Received: {}'.format(event))
        keys = event['ResourceProperties'].keys()
        iam_stackset_param_list = []
        #
        # Build param list from event ResourceProperties
        # IAMStackSetURL, IAMStackSetName and ServiceToken are not input params
        #
        exclude_params_list = (
            'IAMStackSetURL', 'IAMStackSetName', 'ServiceToken', 'CloudTrailBucket', 'EnableIOA',
            'UseExistingCloudtrail')
        for key in keys:
            keyDict = {}
            if key in exclude_params_list:
                pass
            else:
                keyDict['ParameterKey'] = key
                keyDict['ParameterValue'] = event['ResourceProperties'][key]
                iam_stackset_param_list.append(dict(keyDict))

        #
        # Get this account ID
        #

    except Exception as error:
        logger.error(error)
        response_data = {"Status": str(error)}
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
        return

    try:
        response_data = {}
        clist = ['CAPABILITY_NAMED_IAM']
        if event['RequestType'] in ['Create']:
            #
            # Creating stackinstance if IOA enabled.
            #
            if ioa_enabled == 'true':
                desc = 'Create EventBridge rule in child accounts in every region to send CloudTrail events to CrowdStrike'

                stack_op_result = create_self_managed_stackset(iam_stackset_name, desc, iam_stackset_url,
                                                               admin_role_arn,
                                                               iam_stackset_param_list,
                                                               exec_role_arn, clist)
                if stack_op_result['ResponseMetadata']['HTTPStatusCode'] == 200:
                    logger.info('**** Created StackSet {} ****'.format(iam_stackset_name))
                else:
                    logger.info('**** Failed to create StackSet {} ****'.format(iam_stackset_name))
                #
                # Create org wide trail if required.
                # When set to false we will create a new trail and send events to CrowdStike
                #
                if use_existing_cloudtrail == 'false' and trail_exists() == False:
                    cloudtrail_result = create_cloudtrail(ct_bucket, aws_region)
                else:
                    # Don't create org wide trail as customer selected true
                    # Set the result to True and continue
                    cloudtrail_result = True
                if stack_op_result and cloudtrail_result:
                    cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
                else:
                    logger.info('Failed to apply stackset {}'.format(iam_stackset_name))
                    cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")


        elif event['RequestType'] in ['Update']:
            logger.info('Event = ' + event['RequestType'])
            if ioa_enabled == 'true' and use_existing_cloudtrail == 'false' and trail_exists() == False:

                cloudtrail_result = create_cloudtrail(ct_bucket, aws_region)
                logger.info('cloudtrail_result: {}'.format(cloudtrail_result))
            elif ioa_enabled == 'true' and use_existing_cloudtrail == 'true' and trail_exists() == True:
                delete_cloudtrail(aws_region)
            if ioa_enabled == 'false':
                delete_stackset([account_id], iam_stackset_name)
                if trail_exists():
                    delete_cloudtrail(aws_region)

            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")
            return

        elif event['RequestType'] in ['Delete']:
            logger.info('Event = ' + event['RequestType'])
            try:
                delete_stackset([account_id], iam_stackset_name)
                if trail_exists() == True:
                    delete_cloudtrail(aws_region)
                else:
                    logger.info('**** CloudTrail {} does not exist - Skipping deletion ****'.format(CLOUDTRAIL_NAME))
            except Exception as error:
                logger.info('Error deleting StackSet {}'.format(iam_stackset_name))
                pass
            cfnresponse_send(event, context, 'SUCCESS', response_data, "CustomResourcePhysicalID")

    except Exception as e:
        logger.error(e)
        response_data = {"Status": str(e)}
        cfnresponse_send(event, context, 'FAILED', response_data, "CustomResourcePhysicalID")
        return
