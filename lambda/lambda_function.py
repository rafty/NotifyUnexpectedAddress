# -*- coding: utf-8 -*-
import os
import time
import socket
import urllib.parse
import csv
import gzip
import ipaddress
import json
import logging
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
ssm = boto3.client('ssm')
logs = boto3.client('logs')

# environment variable
LOGS_GROUP_NAME = os.environ['LOGS_GROUP_NAME']
LOGS_STREAM_NAME = os.environ['LOGS_STREAM_NAME']

# local cidr
VPC_CIDR = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '198.19.0.0/16']


def reverse_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror as e:
        logger.error(e)
        return 'illegal.domain'


def in_local_cidr(ip_addr):

    ip = ipaddress.ip_address(ip_addr)

    for cidr in VPC_CIDR:
        nw = ipaddress.ip_network(cidr)
        if ip in nw:
            logger.info('ip: {} in local cidr: {}'.format(ip_addr, cidr))
            return True
        else:
            logger.info('ip: {} not in local cidr: {}'.format(ip_addr, cidr))
            continue

    return False


def in_white_list(domain):
    response = ssm.get_parameter(Name='whitelist_for_external_domain')
    white_list = response.get('Parameter').get('Value').split(',')
    logger.info('whitelist: {}'.format(white_list))
    logger.info('whitelist type: {}'.format(type(white_list)))

    for white in white_list:
        if domain.endswith(white):
            return True
        else:
            continue
    return False


def put_log_events(message):

    # events format
    events = [
        dict([('timestamp', int(time.time())*1000), ('message', message)])
    ]

    response = logs.describe_log_streams(
        logGroupName=LOGS_GROUP_NAME,
        logStreamNamePrefix=LOGS_STREAM_NAME)

    logger.info('describe_log_streams: {}'.format(response))

    stream = response['logStreams'][0]
    sequence_token = stream.get('uploadSequenceToken')

    if sequence_token:
        logs.put_log_events(
            logGroupName=LOGS_GROUP_NAME,
            logStreamName=LOGS_STREAM_NAME,
            logEvents=events,
            sequenceToken=sequence_token
        )
    else:
        logs.put_log_events(
            logGroupName=LOGS_GROUP_NAME,
            logStreamName=LOGS_STREAM_NAME,
            logEvents=events
        )
    logger.info('logs.put_log_event: {}'.format(events))


def message_format(messages):
    return '@@'.join(messages)


def check_domain(dest, line):
    domain = reverse_lookup(dest)
    logger.info('domain: {}'.format(domain))

    if in_white_list(domain):
        logger.info('no problem domain: {} <- ip: {}'.format(domain, dest))
    else:
        # alarm
        logger.info('Alarm domain: {} <- ip: {}'.format(domain, dest))
        message = 'Alarm domain: {}, ip-address: {}'.format(domain, dest)
        log_line = json.dumps(line)
        _message = message_format([message, log_line])
        put_log_events(_message)


def vpc_flow_log_object(event):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(
        event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    logger.info('key: {}'.format(key))
    return bucket, key


def lambda_handler(event, context):
    logger.info('event: {}'.format(event))

    bucket, key = vpc_flow_log_object(event)
    try:
        s3.download_file(bucket, key, '/tmp/file.csv.gz')

        with gzip.open('/tmp/file.csv.gz', 'rt') as csv_file:
            f = csv.DictReader(csv_file, delimiter=' ')
            for line in f:
                dest = line.get('dstaddr')
                logger.info('dest ip: {}'.format(dest))

                # dest = '95.211.80.227'  # test
                # dest = '0.0.0.0'  # test

                if not in_local_cidr(dest):
                    check_domain(dest, line)

    except Exception as e:
        logger.error(e)
        raise e
