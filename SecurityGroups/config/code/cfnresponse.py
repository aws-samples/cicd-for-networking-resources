# import json
#
# try:
#     from urllib2 import HTTPError, build_opener, HTTPHandler, Request
# except ImportError:
#     from urllib.error import HTTPError
#     from urllib.request import build_opener, HTTPHandler, Request
#
#
# SUCCESS = "SUCCESS"
# FAILED = "FAILED"
#
#
# def send(event, context, response_status, reason=None, response_data=None, physical_resource_id=None):
#     response_data = response_data or {}
#     response_body = json.dumps(
#         {
#             'Status': response_status,
#             'Reason': reason or "See the details in CloudWatch Log Stream: " + context.log_stream_name,
#             'PhysicalResourceId': physical_resource_id or context.log_stream_name,
#             'StackId': event['StackId'],
#             'RequestId': event['RequestId'],
#             'LogicalResourceId': event['LogicalResourceId'],
#             'Data': response_data
#         }
#     )
#
#     opener = build_opener(HTTPHandler)
#     request = Request(event['ResponseURL'], data=response_body)
#     request.add_header('Content-Type', '')
#     request.add_header('Content-Length', len(response_body))
#     request.get_method = lambda: 'PUT'
#     try:
#         response = opener.open(request)
#         print("Status code: {}".format(response.getcode()))
#         print("Status message: {}".format(response.msg))
#         return True
#     except HTTPError as exc:
#         print("Failed executing HTTP request: {}".format(exc.code))
#         return False


# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from __future__ import print_function
import urllib3
import json

SUCCESS = "SUCCESS"
FAILED = "FAILED"

http = urllib3.PoolManager()


def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):
    responseUrl = event['ResponseURL']

    print(responseUrl)

    responseBody = {
        'Status' : responseStatus,
        'Reason' : reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),
        'PhysicalResourceId' : physicalResourceId or context.log_stream_name,
        'StackId' : event['StackId'],
        'RequestId' : event['RequestId'],
        'LogicalResourceId' : event['LogicalResourceId'],
        'NoEcho' : noEcho,
        'Data' : responseData
    }

    json_responseBody = json.dumps(responseBody)

    print("Response body:")
    print(json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = http.request('PUT', responseUrl, headers=headers, body=json_responseBody)
        print("Status code:", response.status)


    except Exception as e:

        print("send(..) failed executing http.request(..):", e)