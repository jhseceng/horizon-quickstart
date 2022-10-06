import logging
import os
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)
iam_stackset = os.environ["IAMStackSet"]
ioa_stackset = os.environ["IOAStackSet"]
ioa_enabled = os.environ["EnableIOA"]

def get_regions():
    client = boto3.client('ec2')
    regions = [region['RegionName'] for region in client.describe_regions()['Regions']]
    return regions

def lambda_handler(event, context):
    logger.info('Got event {}'.format(event))
    logger.info('Context {}'.format(context))
    masterAcct = event['account']
    eventDetails = event['detail']
    regionName = eventDetails['awsRegion']
    eventName = eventDetails['eventName']
    srvEventDetails = eventDetails['serviceEventDetails']
    if eventName == 'CreateManagedAccount':
        newAccInfo = srvEventDetails['createManagedAccountStatus']
        cmdStatus = newAccInfo['state']
        if cmdStatus == 'SUCCEEDED':
            '''Sucessful event recieved'''
            ouInfo = newAccInfo['organizationalUnit']
            ouName = ouInfo['organizationalUnitName']
            odId = ouInfo['organizationalUnitId']
            accId = newAccInfo['account']['accountId']
            accName = newAccInfo['account']['accountName']
            CFT = boto3.client('cloudformation')
            try:
                CFT.create_stack_instances(StackSetName=iam_stackset, Accounts=[accId], Regions=[regionName])
                logger.info('Processed {} Sucessfully'.format(iam_stackset))
            except Exception as e:
                logger.error('Unable to create stack :{}, REASON: {}'.format(iam_stackset, e))
            if ioa_enabled == 'true':
                try:
                    region_list = get_regions()
                    if region_list:
                        CFT.create_stack_instances(
                            StackSetName=ioa_stackset,
                            OperationPreferences={
                                'RegionConcurrencyType': 'PARALLEL',
                                'FailureTolerancePercentage': 100,
                                'MaxConcurrentCount': 20,
                            },
                            Accounts=[accId],
                            Regions=region_list
                            )
                        logger.info('Processed {} Sucessfully'.format(ioa_stackset))
                    else:
                        logger.info('Found no active regions to apply stackset {}'.format(ioa_stackset))
                except Exception as e:
                    logger.error('Unable to create stack :{}, REASON: {}'.format(ioa_stackset, e))
        else:
            '''Unsucessful event recieved'''
            logger.info('Unsucessful Event Recieved. SKIPPING :{}'.format(event))
            return (False)
    else:
        logger.info('Control Tower Event Captured but no action required :{}'.format(event))
