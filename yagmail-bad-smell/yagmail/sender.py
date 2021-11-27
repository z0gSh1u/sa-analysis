# when there is a bcc a different message has to be sent to the bcc
# person, to show that they are bcc'ed

import random
import time
import logging
import smtplib

from yagmail.log import get_logger
from yagmail.utils import find_user_home_path
# from yagmail.oauth2 import get_oauth2_info, get_oauth_string
from yagmail.headers import resolve_addresses
from yagmail.validate import validate_email_with_regex
from yagmail.password import handle_password
from yagmail.headers import make_addr_alias_user

"""
Adapted from:
http://blog.macuyiko.com/post/2016/how-to-send-html-mails-with-oauth2-and-gmail-in-python.html

1. Generate and authorize an OAuth2 (generate_oauth2_token)
2. Generate a new access tokens using a refresh token(refresh_token)
3. Generate an OAuth2 string to use for login (access_token)
"""
import os
import base64
import json
import getpass

try:
    from urllib.parse import urlencode, quote, unquote
    from urllib.request import urlopen
except ImportError:
    from urllib import urlencode, quote, unquote, urlopen

try:
    input = raw_input
except NameError:
    pass

GOOGLE_ACCOUNTS_BASE_URL = 'https://accounts.google.com'
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'


def command_to_url(command):
    return '%s/%s' % (GOOGLE_ACCOUNTS_BASE_URL, command)


def url_format_params(params):
    param_fragments = []
    for param in sorted(params.items(), key=lambda x: x[0]):
        escaped_url = quote(param[1], safe='~-._')
        param_fragments.append('%s=%s' % (param[0], escaped_url))
    return '&'.join(param_fragments)


def generate_permission_url(client_id):
    params = {}
    params['client_id'] = client_id
    params['redirect_uri'] = REDIRECT_URI
    params['scope'] = 'https://mail.google.com/'
    params['response_type'] = 'code'
    return '%s?%s' % (command_to_url('o/oauth2/auth'), url_format_params(params))


def call_authorize_tokens(client_id, client_secret, authorization_code):
    params = {}
    params['client_id'] = client_id
    params['client_secret'] = client_secret
    params['code'] = authorization_code
    params['redirect_uri'] = REDIRECT_URI
    params['grant_type'] = 'authorization_code'
    request_url = command_to_url('o/oauth2/token')
    encoded_params = urlencode(params).encode('UTF-8')
    response = urlopen(request_url, encoded_params).read().decode('UTF-8')
    return json.loads(response)


def call_refresh_token(client_id, client_secret, refresh_token):
    params = {}
    params['client_id'] = client_id
    params['client_secret'] = client_secret
    params['refresh_token'] = refresh_token
    params['grant_type'] = 'refresh_token'
    request_url = command_to_url('o/oauth2/token')
    encoded_params = urlencode(params).encode('UTF-8')
    response = urlopen(request_url, encoded_params).read().decode('UTF-8')
    return json.loads(response)


def generate_oauth2_string(username, access_token, as_base64=False):
    auth_string = 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)
    if as_base64:
        auth_string = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
    return auth_string


def get_authorization(google_client_id, google_client_secret):
    permission_url = generate_permission_url(google_client_id)
    print('Navigate to the following URL to auth:\n' + permission_url)
    authorization_code = input('Enter verification code: ')
    response = call_authorize_tokens(google_client_id, google_client_secret, authorization_code)
    return response['refresh_token'], response['access_token'], response['expires_in']


def refresh_authorization(google_client_id, google_client_secret, google_refresh_token):
    response = call_refresh_token(google_client_id, google_client_secret, google_refresh_token)
    return response['access_token'], response['expires_in']


def get_oauth_string(user, oauth2_info):
    access_token, expires_in = refresh_authorization(**oauth2_info)
    auth_string = generate_oauth2_string(user, access_token, as_base64=True)
    return auth_string


def get_oauth2_info(oauth2_file):
    oauth2_file = os.path.expanduser(oauth2_file)
    if os.path.isfile(oauth2_file):
        with open(oauth2_file) as f:
            oauth2_info = json.load(f)
        try:
            oauth2_info = oauth2_info["installed"]
        except KeyError:
            return oauth2_info
        email_addr = input("Your 'email address': ")
        google_client_id = oauth2_info["client_id"]
        google_client_secret = oauth2_info["client_secret"]
        google_refresh_token, _, _ = get_authorization(google_client_id, google_client_secret)
        oauth2_info = {
            "email_address": email_addr,
            "google_client_id": google_client_id.strip(),
            "google_client_secret": google_client_secret.strip(),
            "google_refresh_token": google_refresh_token.strip(),
        }
        with open(oauth2_file, "w") as f:
            json.dump(oauth2_info, f)
    else:
        print("If you do not have an app registered for your email sending purposes, visit:")
        print("https://console.developers.google.com")
        print("and create a new project.\n")
        email_addr = input("Your 'email address': ")
        google_client_id = input("Your 'google_client_id': ")
        google_client_secret = getpass.getpass("Your 'google_client_secret': ")
        google_refresh_token, _, _ = get_authorization(google_client_id, google_client_secret)
        oauth2_info = {
            "email_address": email_addr,
            "google_client_id": google_client_id.strip(),
            "google_client_secret": google_client_secret.strip(),
            "google_refresh_token": google_refresh_token.strip(),
        }
        with open(oauth2_file, "w") as f:
            json.dump(oauth2_info, f)
    return oauth2_info


# MODIFY
from message import EMailBuilder

class SMTP:
    """ :class:`yagmail.SMTP` is a magic wrapper around
    ``smtplib``'s SMTP connection, and allows messages to be sent."""

    def __init__(
        self,
        user=None,
        password=None,
        host="smtp.gmail.com",
        port=None,
        smtp_starttls=None,
        smtp_ssl=True,
        smtp_set_debuglevel=0,
        smtp_skip_login=False,
        encoding="utf-8",
        oauth2_file=None,
        soft_email_validation=True,
        **kwargs
    ):
        self.log = get_logger()
        self.set_logging()
        self.soft_email_validation = soft_email_validation
        if oauth2_file is not None:
            oauth2_info = get_oauth2_info(oauth2_file)
            if user is None:
                user = oauth2_info["email_address"]
        if smtp_skip_login and user is None:
            user = ""
        elif user is None:
            user = find_user_home_path()
        self.user, self.useralias = make_addr_alias_user(user)
        if soft_email_validation:
            validate_email_with_regex(self.user)
        self.is_closed = None
        self.host = host
        self.port = str(port) if port is not None else "465" if smtp_ssl else "587"
        self.smtp_starttls = smtp_starttls
        self.ssl = smtp_ssl
        self.smtp_skip_login = smtp_skip_login
        self.debuglevel = smtp_set_debuglevel
        self.encoding = encoding
        self.kwargs = kwargs
        self.cache = {}
        self.unsent = []
        self.num_mail_sent = 0
        self.oauth2_file = oauth2_file
        self.credentials = password if oauth2_file is None else oauth2_info

        # MOCK
        self.slpTimesTot = 0.0
        self.failureCount = 0
        self.errors = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.is_closed:
            self.close()
        return False

    @property
    def connection(self):
        return smtplib.SMTP_SSL if self.ssl else smtplib.SMTP

    @property
    def starttls(self):
        if self.smtp_starttls is None:
            return False if self.ssl else True
        return self.smtp_starttls

    def set_logging(self, log_level=logging.ERROR, file_path_name=None):
        """
        This function allows to change the logging backend, either output or file as backend
        It also allows to set the logging level (whether to display only critical/error/info/debug.
        for example::

            yag = yagmail.SMTP()
            yag.set_logging(yagmail.logging.DEBUG)  # to see everything

        and::

            yagmail.set_logging(yagmail.logging.DEBUG, 'somelocalfile.log')

        lastly, a log_level of :py:class:`None` will make sure there is no I/O.
        """
        self.log = get_logger(log_level, file_path_name)

    def prepare_send(
        self,
        to=None,
        subject=None,
        contents=None,
        attachments=None,
        cc=None,
        bcc=None,
        headers=None,
        prettify_html=True,
        message_id=None,
        group_messages=True,
    ):
        addresses = resolve_addresses(self.user, self.useralias, to, cc, bcc)

        if self.soft_email_validation:
            for email_addr in addresses["recipients"]:
                validate_email_with_regex(email_addr)

        builder = EMailBuilder(
            self.user,
            self.useralias,
            addresses,
            subject,
            contents,
            attachments,
            headers,
            self.encoding,
            prettify_html,
            message_id,
            group_messages,
        )

        msg = builder.prepare_message()

        recipients = addresses["recipients"]
        msg_string = msg.as_string()
        return recipients, msg_string

    def send(
        self,
        to=None,
        subject=None,
        contents=None,
        attachments=None,
        cc=None,
        bcc=None,
        preview_only=False,
        headers=None,
        prettify_html=True,
        message_id=None,
        group_messages=True,
    ):
        """ Use this to send an email with gmail"""
        self.login()

        recipients, msg_string = self.prepare_send(
            to,
            str(subject) if type(subject) is int else subject,
            contents,
            attachments,
            cc,
            bcc,
            headers,
            prettify_html,
            message_id,
            group_messages,
        )
        if preview_only:
            return (recipients, msg_string)
        return self._attempt_send(recipients, msg_string)

    def _attempt_send(self, recipients, msg_string):
        attempts = 0
        while attempts < 3:
            try:
                result = self.smtp.sendmail(self.user, recipients, msg_string)
                self.log.info("Message sent to %s", recipients)
                self.num_mail_sent += 1
                return result
            except smtplib.SMTPServerDisconnected as e:
                self.log.error(e)
                attempts += 1
                time.sleep(attempts * 3)
        self.unsent.append((recipients, msg_string))
        return False

    def send_unsent(self):
        """
        Emails that were not being able to send will be stored in :attr:`self.unsent`.
        Use this function to attempt to send these again
        """
        for i in range(len(self.unsent)):
            recipients, msg_string = self.unsent.pop(i)
            self._attempt_send(recipients, msg_string)

    def close(self):
        """ Close the connection to the SMTP server """
        self.is_closed = True
        try:
            self.smtp.quit()
        except (TypeError, AttributeError, smtplib.SMTPServerDisconnected):
            pass

    def login(self):
        if self.oauth2_file is not None:
            self._login_oauth2(self.credentials)
        else:
            self._login(self.credentials)

    def _login(self, password):
        """
        Login to the SMTP server using password. `login` only needs to be manually run when the
        connection to the SMTP server was closed by the user.
        """
        self.smtp = self.connection(self.host, self.port, **self.kwargs)
        self.smtp.set_debuglevel(self.debuglevel)
        if self.starttls:
            self.smtp.ehlo()
            if self.starttls is True:
                self.smtp.starttls()
            else:
                self.smtp.starttls(**self.starttls)
            self.smtp.ehlo()
        self.is_closed = False
        if not self.smtp_skip_login:
            password = self.handle_password(self.user, password)
            self.smtp.login(self.user, password)
        self.log.info("Connected to SMTP @ %s:%s as %s", self.host, self.port, self.user)

    @staticmethod
    def handle_password(user, password):
        return handle_password(user, password)

    @staticmethod
    def get_oauth_string(user, oauth2_info):
        return get_oauth_string(user, oauth2_info)

    def _login_oauth2(self, oauth2_info):
        if "email_address" in oauth2_info:
            oauth2_info.pop("email_address")
        self.smtp = self.connection(self.host, self.port, **self.kwargs)
        try:
            self.smtp.set_debuglevel(self.debuglevel)
        except AttributeError:
            pass
        auth_string = self.get_oauth_string(self.user, oauth2_info)
        self.smtp.ehlo(oauth2_info["google_client_id"])
        if self.starttls is True:
            self.smtp.starttls()
        self.smtp.docmd("AUTH", "XOAUTH2 " + auth_string)

    def feedback(self, message="Awesome features! You made my day! How can I contribute?"):
        """ Most important function. Please send me feedback :-) """
        self.send("kootenpv@gmail.com", "Yagmail feedback", message)

    def __del__(self):
        try:
            if not self.is_closed:
                self.close()
        except AttributeError:
            pass
