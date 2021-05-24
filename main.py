import sys
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.by import By
from requests_oauthlib import OAuth1Session
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# IMPORTANT!
# Insert your Consumer Key and Consumer Secret Key here.
consumer_key = 'xxxxINSERTHERExxxx'
consumer_secret = 'xxxxINSERTHERExxxx'

REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token'
ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token'
AUTHORIZATION_URL = 'https://api.twitter.com/oauth/authorize'
SIGNIN_URL = 'https://api.twitter.com/oauth/authenticate'

def execute(username, password):
    print('Starting Authorisation...')

    oauth_client = OAuth1Session(consumer_key, client_secret=consumer_secret, callback_uri='oob')

    print('Requesting Token...')

    # Getting request token and authorisation link.
    resp = oauth_client.fetch_request_token(REQUEST_TOKEN_URL)
    url = oauth_client.authorization_url(AUTHORIZATION_URL)

    options = Options()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')

    # If you want to disable Headless mode then remove "options=options" below.
    browser = webdriver.Chrome('/Users/benbaessler/Documents/chromedriver', options=options)
    browser.get(url)

    print('Logging in...')
    # Automating the process of granting access to your Twitter App.
    username_input = browser.find_element_by_id('username_or_email')
    password_input = browser.find_element_by_id('password')
    submit_btn = browser.find_element_by_id('allow')

    username_input.send_keys(username)
    password_input.send_keys(password)
    submit_btn.click()

    # Checking if the login information was invalid.
    if 'https://twitter.com/login/error?username_or_email' in browser.current_url:
        print('Error: Invalid login! @{}'.format(username))
        sys.exit()

    # Automatically getting Verification PIN and passing it to the OAuth Client.
    try:
        elem = WebDriverWait(browser, 10).until(EC.presence_of_element_located((By.XPATH, '//*[@id="oauth_pin"]/p/kbd/code')))
    except TimeoutException:
        print('Timed out.')
        sys.exit()

    print('Getting verification PIN...')
    pincode = elem.text

    print('Generating and signing request for access token...')

    oauth_client = OAuth1Session(consumer_key, client_secret=consumer_secret, resource_owner_key=resp.get('oauth_token'),resource_owner_secret=resp.get('oauth_token_secret'), verifier=pincode)
    try:
        resp = oauth_client.fetch_access_token(ACCESS_TOKEN_URL)
    except ValueError as e:
        raise 'Invalid response from Twitter requesting temporary token: {0}'.format(e)

    print('''
    OAuth token: {}
    OAuth token secret: {}
    '''.format(resp.get('oauth_token'), resp.get('oauth_token_secret')))

    # return resp.get('oauth_token'), resp.get('oauth_token_secret')



if __name__ == '__main__':
    try:
        args = sys.argv[1].split(':')
        if ':' not in sys.argv[1]:
            print('Invalid format -> username:password')
            sys.exit()
        execute(args[0], args[1])
    except IndexError:
        print('User Login missing -> python auth.py username:password')
