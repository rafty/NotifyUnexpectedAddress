# -*- coding: utf-8 -*-
import os
import json
import datetime
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

logs = boto3.client('logs')
sns = boto3.client('sns')


SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']


def extract_sns_parameter(event):
    message = json.loads(event['Records'][0]['Sns']['Message'])
    metric_name = message['Trigger']['MetricName']
    metric_name_space = message['Trigger']['Namespace']
    state_change_time = message['StateChangeTime']
    period = message['Trigger']['Period']

    return {
        'message': message,
        'metric_name': metric_name,
        'metric_name_space': metric_name_space,
        'StateChangeTime': state_change_time,
        'Period': period
    }


def extract_logs_parameter(sns_params):
    metric_filters = logs.describe_metric_filters(
        metricName=sns_params['metric_name'],
        metricNamespace=sns_params['metric_name_space']
    )

    log_group_name = metric_filters['metricFilters'][0]['logGroupName']
    filter_pattern = metric_filters['metricFilters'][0]['filterPattern']

    return {
        'logGroupName': log_group_name,
        'filterPattern': filter_pattern
    }


def logs_window(sns_params):
    # e.g. "StateChangeTime": "2019-10-09T03:51:12.608+0000",
    period = sns_params['Period']
    last_window = period * 2
    end_time = datetime.datetime.strptime(sns_params['StateChangeTime'],
                                          '%Y-%m-%dT%H:%M:%S.%f%z')
    start_time = end_time - datetime.timedelta(seconds=last_window)
    alarm_end_time = int(end_time.timestamp()) * 1000  # millisecond
    alarm_start_time = int(start_time.timestamp()) * 1000  # millisecond
    return {
       'startTime': alarm_start_time,
       'endTime': alarm_end_time
    }


def message_format(message):
    try:
        phrases = message.split('@@')
    except ValueError:
        return message

    phrases.insert(0, 'Alarm!!!')
    phrases.insert(1, 'Accessing an unexpected address. Please confirm.')

    try:
        _dict = json.loads(phrases[-1])
        phrases[-1] = json.dumps(_dict, indent=4)
        phrases.insert(-1, '\n')
        phrases.insert(-1, 'VPC Flow Logs:')

    except Exception as e:
        logger.warning('Json decode Error!! {}'.format(e))

    return '\n'.join(phrases)


def lambda_handler(event, context):
    logger.info('event: {}'.format(event))

    sns_params = extract_sns_parameter(event)
    logs_params = extract_logs_parameter(sns_params)
    window = logs_window(sns_params)

    try:
        response = logs.filter_log_events(
            logGroupName=logs_params.get('logGroupName'),
            filterPattern=logs_params.get('filterPattern'),
            startTime=window.get('startTime'),
            endTime=window.get('endTime')
        )

        messages = response['events']

        for message in messages:
            print('message: {}'.format(message))
            _message = message_format(message['message'])

            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=_message,
                Subject='Alert! Accessing an IP address not in WhiteList'
            )

    except Exception as e:
        logger.error(e)
        raise e
