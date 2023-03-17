from . import BaseTestsClass
from login.db import get_db
from flask import session
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
from . import page


class LoginTests(BaseTestsClass):
    
    def test_LoginRoot(self):
        self.driver.get("http://localhost:5000/auth/login")
        assert "Log In" in self.driver.title
        passwd = self.driver.find_element(By.ID, "password")
        passwd.clear()
        passwd.send_keys("root")
        user = self.driver.find_element(By.ID, "username")
        user.clear()
        user.send_keys("root")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(self.driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/user/root"))
        actualUrl = "http://localhost:5000/user/root"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)

    def test_registerNonRegisteredUser(self):
        driver = self.driver
        driver.get("http://localhost:5000/auth/register")
        assert "Register" in driver.title
        passwd = driver.find_element(By.NAME, "password")
        passwd.clear()
        passwd.send_keys("joje")
        user = driver.find_element(By.NAME, "username")
        user.clear()
        user.send_keys("joje")
        firstname = driver.find_element(By.NAME, "firstname")
        firstname.send_keys("joje")
        secondname = driver.find_element(By.NAME, "secondname")
        secondname.send_keys("joje")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/auth/login"))
        actualUrl = "http://localhost:5000/auth/login"
        expectedUrl= driver.current_url
        self.assertEqual(expectedUrl,actualUrl)

    def test_loginRegisteredNonAuthorizedUser(self):
        self.test_registerNonRegisteredUser()
        self.driver.get("http://localhost:5000/auth/login")
        assert "Log In" in self.driver.title
        passwd = self.driver.find_element(By.ID, "password")
        passwd.clear()
        passwd.send_keys("joje")
        user = self.driver.find_element(By.ID, "username")
        user.clear()
        user.send_keys("joje")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(self.driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/auth/login"))
        actualUrl = "http://localhost:5000/auth/login"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        element = self.driver.find_element(By.TAG_NAME, 'section')
        elements = element.find_elements(By.TAG_NAME, 'div')
        for e in elements:
            if (e.text == "User 'joje' needs autentication from admin."):
                self.assertEqual(e.text,"User 'joje' needs autentication from admin.")

    def test_loginNonRegisteredUser(self):
        driver = self.driver
        driver.get("http://localhost:5000/auth/login")
        assert "Log In" in driver.title
        passwd = driver.find_element(By.ID, "password")
        passwd.clear()
        passwd.send_keys("joje")
        user = driver.find_element(By.ID, "username")
        user.clear()
        user.send_keys("joje")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/auth/login"))
        actualUrl = "http://localhost:5000/auth/login"
        expectedUrl= driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        element = driver.find_element(By.TAG_NAME, 'section')
        elements = element.find_elements(By.TAG_NAME, 'div')
        for e in elements:
            if (e.text == "User doesn't exist."):
                self.assertEqual(e.text,"User doesn't exist.")

    def test_registerRoot(self):
        driver = self.driver
        driver.get("http://localhost:5000/auth/register")
        assert "Register" in driver.title
        passwd = driver.find_element(By.NAME, "password")
        passwd.clear()
        passwd.send_keys("root")
        user = driver.find_element(By.NAME, "username")
        user.clear()
        user.send_keys("root")
        firstname = driver.find_element(By.NAME, "firstname")
        firstname.send_keys("dsfs")
        secondname = driver.find_element(By.NAME, "secondname")
        secondname.send_keys("dsfsd")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/auth/register"))
        actualUrl = "http://localhost:5000/auth/register"
        expectedUrl= driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        element = driver.find_element(By.TAG_NAME, 'section')
        elements = element.find_elements(By.TAG_NAME, 'div')
        for e in elements:
            if (e.text == "User 'root' is already registered."):
                self.assertEqual(e.text,"User 'root' is already registered.")
    
    def test_loginIncorrectPassword(self):
        driver = self.driver
        driver.get("http://localhost:5000/auth/login")
        assert "Log In" in driver.title
        passwd = driver.find_element(By.ID, "password")
        passwd.clear()
        passwd.send_keys("root")
        user = driver.find_element(By.ID, "username")
        user.clear()
        user.send_keys("joje")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/auth/login"))
        actualUrl = "http://localhost:5000/auth/login"
        expectedUrl= driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        element = driver.find_element(By.TAG_NAME, 'section')
        elements = element.find_elements(By.TAG_NAME, 'div')
        for e in elements:
            if (e.text == "Incorrect password."):
                self.assertEqual(e.text,"Incorrect password.")

    def test_rootRejectUser(self):
        self.test_registerNonRegisteredUser()
        self.driver.get("http://localhost:5000/auth/login")
        assert "Log In" in self.driver.title
        passwd = self.driver.find_element(By.ID, "password")
        passwd.clear()
        passwd.send_keys("root")
        user = self.driver.find_element(By.ID, "username")
        user.clear()
        user.send_keys("root")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(self.driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/user/root"))
        actualUrl = "http://localhost:5000/user/root"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        user_button = self.driver.find_element(By.ID, "user")
        user_button.click()
        wait.until(EC.url_to_be("http://localhost:5000/root/users"))
        actualUrl = "http://localhost:5000/root/users"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        reject_button = self.driver.find_element(By.NAME, "reject")
        reject_button.click()
        wait.until(EC.url_to_be("http://localhost:5000/root/users"))
        actualUrl = "http://localhost:5000/root/users"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)


    def test_RootCreateProyect(self):
        self.driver.get("http://localhost:5000/auth/login")
        assert "Log In" in self.driver.title
        passwd = self.driver.find_element(By.ID, "password")
        passwd.clear()
        passwd.send_keys("root")
        user = self.driver.find_element(By.ID, "username")
        user.clear()
        user.send_keys("root")
        user.send_keys(Keys.RETURN)
        wait = WebDriverWait(self.driver, 10)
        wait.until(EC.url_to_be("http://localhost:5000/user/root"))
        actualUrl = "http://localhost:5000/user/root"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        user_button = self.driver.find_element(By.ID, "proyect")
        user_button.click()
        wait.until(EC.url_to_be("http://localhost:5000/root/proyects"))
        actualUrl = "http://localhost:5000/root/proyects"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
        create_proyect_button = self.driver.find_element(By.NAME, "create-proyect")
        create_proyect_button.click()
        proyect_description = self.driver.find_element(By.ID, "description")
        proyect_description.send_keys("testproyect")
        proyect_starting_date = self.driver.find_element(By.ID, "starting-date")
        proyect_starting_date.click()
        proyect_starting_date.send_keys("2023-03-10")
        proyect_end_date = self.driver.find_element(By.ID, "end-date")
        proyect_end_date.click()
        proyect_end_date.send_keys("2023-03-15")
        proyect_description.send_keys(Keys.RETURN)
        wait.until(EC.url_to_be("http://localhost:5000/root/proyects"))
        actualUrl = "http://localhost:5000/root/proyects"
        expectedUrl= self.driver.current_url
        self.assertEqual(expectedUrl,actualUrl)
