# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging
import os
from unittest.mock import patch, MagicMock, call

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from api import alogging

REQUEST_HEADERS_TEST = {'authorization': 'Basic d2F6dWg6cGFzc3dvcmQxMjM='}  # wazuh:password123
AUTH_CONTEXT_TEST = {'auth_context': 'example'}
HASH_AUTH_CONTEXT_TEST = '020efd3b53c1baf338cf143fad7131c3'


@pytest.mark.parametrize('side_effect, user', [
    ('unknown', ''),
    (None, ''),
    (None, 'wazuh')
])
@patch('api.alogging.json.dumps')
def test_accesslogger_log(mock_dumps, side_effect, user):
    """Test expected methods are called when using log(). Also test that the user is logged properly.

    Parameters
    ----------
    side_effect : function
        Side effect used in the decode_token mock.
    user : str
        User returned by the request.get function of alogging.py, which is mocked using a class.
    """

    # Create a class with a mocked get method for request
    class MockedRequest(MagicMock):
        headers = REQUEST_HEADERS_TEST if side_effect is None else {}

        def get(self, *args, **kwargs):
            return user

    # Mock decode_token and logger.info
    with patch('logging.Logger.info') as mock_logger_info:

        # Create an AccessLogger object and log a mocked call
        test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
        test_access_logger.log(request=MockedRequest(), response=MagicMock(), time=0.0)

        log_message = mock_logger_info.call_args.args[0].split(" ")

        # If not user, decode_token must be called to get the user and logger.info must be called with the user
        # if we have token_info or UNKNOWN_USER if not
        if not user:
            expected_user = 'wazuh' if side_effect is None else alogging.UNKNOWN_USER_STRING
            assert log_message[0] == expected_user

        # If user, logger.info must be called with the user
        else:
            assert log_message[0] == user


@pytest.mark.parametrize('request_path, token_info, request_body', [
    ('/agents', {'hash_auth_context': HASH_AUTH_CONTEXT_TEST}, {}),  # Test a normal request logs the auth context hash
    ('/security/user/authenticate/run_as', {'other_key': 'other_value'},
     AUTH_CONTEXT_TEST),  # Test a login request generates and logs the auth context hash
    ('/security/user/authenticate', None, {})  # Test any other call without auth context does not log the hash
])
def test_accesslogger_log_hash_auth_context(request_path, token_info, request_body):
    """Test expected methods are called when using log(). Also test that the auth context hash is logged properly.

    Parameters
    ----------
    request_path : str
        Path used in the custom request.
    token_info : dict
        Dictionary corresponding to the token information. If token_info is None, we simulate that no token was given.
    request_body : dict
        Request body used in the custom request.
    """

    # Create a class with custom methods for request
    class CustomRequest:
        def __init__(self):
            self.request_dict = {'token_info': token_info} if token_info else {}
            self.path = request_path
            self.body = request_body
            self.query = {'q': 'test'}
            self.remote = 'test'
            self.method = 'test'
            self.user = 'test'

        def __contains__(self, key):
            return key in self.request_dict

        def __getitem__(self, key):
            return self.request_dict[key]

        def get(self, *args, **kwargs):
            return getattr(self, args[0]) if args[0] in self.__dict__.keys() else args[1]

    # Mock logger.info
    with patch('logging.Logger.info') as mock_logger_info:
        # Create an AccessLogger object and log a mocked call
        request = CustomRequest()
        test_access_logger = alogging.AccessLogger(logger=logging.getLogger('test'), log_format=MagicMock())
        test_access_logger.log(request=request, response=MagicMock(), time=0.0)

        log_message = mock_logger_info.call_args.args[0].split(" ")

        # Test authorization context hash is being logged
        if (token_info and token_info.get('hash_auth_context')) or \
                (request_path == "/security/user/authenticate/run_as" and request_body):
            assert log_message[1] == HASH_AUTH_CONTEXT_TEST
        else:
            assert log_message[1] == request.remote


@patch('wazuh.core.wlogging.WazuhLogger.__init__')
def test_apilogger_init(mock_wazuhlogger):
    """Check parameters are as expected when calling __init__ method"""
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level='info',
                       logger_name='wazuh')

    assert mock_wazuhlogger.call_args.kwargs['log_path'] == current_logger_path
    assert not mock_wazuhlogger.call_args.kwargs['foreground_mode']
    assert mock_wazuhlogger.call_args.kwargs['debug_level'] == 'info'
    assert mock_wazuhlogger.call_args.kwargs['logger_name'] == 'wazuh'
    assert mock_wazuhlogger.call_args.kwargs['tag'] == '{asctime} {levelname}: {message}'

    os.path.exists(current_logger_path) and os.remove(current_logger_path)


@pytest.mark.parametrize('debug_level, expected_level', [
    ('info', logging.INFO),
    ('debug2', 5),
    ('debug', logging.DEBUG),
    ('critical', logging.CRITICAL),
    ('error', logging.ERROR),
    ('warning', logging.WARNING),
])
@patch('api.alogging.logging.Logger.setLevel')
def test_apilogger_setup_logger(mock_logger, debug_level, expected_level):
    """Check loggin level is as expected"""
    current_logger_path = os.path.join(os.path.dirname(__file__), 'testing.log')
    logger = alogging.APILogger(log_path=current_logger_path, foreground_mode=False, debug_level=debug_level,
                                logger_name='wazuh')
    logger.setup_logger()
    assert mock_logger.call_args == call(expected_level)

    os.path.exists(current_logger_path) and os.remove(current_logger_path)
