import time
from selenium.webdriver.support import expected_conditions as EC

from selenium import webdriver
from selenium.webdriver import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
import json

from selenium.webdriver.common.devtools.v85.indexed_db import Key
from selenium.webdriver.support.wait import WebDriverWait

cve_file = 'cve.json'


def create_cve_json():
    ser = Service(r'C:\geckodriver.exe')
    driver = webdriver.Firefox(service=ser)
    driver.get(
        "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
    number_cve = int(driver.find_element(By.XPATH, '//*[@id="pagingb"]/b').text)
    '''
    json_data = []
    with open('cve.json', 'w', encoding='utf-8') as f:
        json.dump(json_data, f, ensure_ascii=False, indent=4)
    f.close()
    '''
    ok = True
    page_num = 327
    cve_cpt = 16350
    while ok:
        with open(cve_file, encoding='utf-8') as json_file:
            json_data = json.load(json_file)
        json_file.close()

        page_num = page_num + 1
        driver.get(
            "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=" + str(
                page_num) + "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
        rows = driver.find_element(By.ID, "vulnslisttable").find_element(By.TAG_NAME, 'tbody').find_elements(
            By.TAG_NAME, 'tr')[1:]
        for o in range(0, len(rows), 2):

            cve_cpt = cve_cpt + 1
            row = rows.pop(0)
            link = row.find_element(By.XPATH, 'td[2]/a').get_attribute('href')
            columns = row.find_elements(By.TAG_NAME, 'td')
            actual_cve_number = int(columns.pop(0).text)

            if actual_cve_number > number_cve:
                ok = False
                break
            cve_data = {'CVE_ID': '', 'CWE_ID': '', '#': '', 'Vulnerability': '', 'Publish Date': '', 'Update Date': '',
                        'Score': '', 'Gained Access Level': '', 'Access': '', 'Complexity': '', 'Authentication': '',
                        'Conf': '', 'Integ': '', 'Avail': '', 'Description': '', 'Products Affected': []}

            cve_data['Description'] = rows.pop(0).find_element(By.TAG_NAME, 'td').text
            for i in range(0, 13):
                cve_data[list(cve_data)[i]] = columns.pop(0).text

            driver.execute_script('window.open("' + link + '","_blank");')
            driver.switch_to.window(driver.window_handles[1])

            try:
                tab_product_affected = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.ID, "vulnprodstable"))).find_element(By.TAG_NAME,
                                                                                            'tbody').find_elements(
                    By.TAG_NAME, 'tr')[1:]
                for tr in tab_product_affected:
                    data_product = {'id': '', 'Product Type': '', 'Vendor': '', 'Product': '', 'Version': '',
                                    'Update': '', 'Edition': '', 'Language': ''}
                    tds = tr.find_elements(By.TAG_NAME, 'td')
                    for j in range(0, 7):
                        data_product[list(data_product)[j]] = tds.pop(0).text
                    cve_data['Products Affected'].append(data_product)
            except:
                print("")
            driver.close()
            driver.switch_to.window(driver.window_handles[0])
            print(cve_cpt, "/", number_cve)
            json_data.append(cve_data)

        with open(cve_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, ensure_ascii=False, indent=4)
        f.close()
    driver.close()


def cve_json_maj():
    ser = Service(r'C:\geckodriver.exe')
    driver = webdriver.Firefox(service=ser)
    driver.get(
        "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
    number_cve = int(driver.find_element(By.XPATH, '//*[@id="pagingb"]/b').text)
    with open(cve_file, encoding='utf-8') as json_file:
        json_data = json.load(json_file)
    json_file.close()

    ok = True
    page_num = 0
    cve_cpt = 0
    while ok:
        page_num = page_num + 1
        driver.get(
            "https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=" + str(
                page_num) + "&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
        rows = driver.find_element(By.ID, "vulnslisttable").find_element(By.TAG_NAME, 'tbody').find_elements(
            By.TAG_NAME, 'tr')[1:]
        for o in range(0, len(rows), 2):

            cve_cpt = cve_cpt + 1
            row = rows.pop(0)
            link = row.find_element(By.XPATH, 'td[2]/a').get_attribute('href')
            columns = row.find_elements(By.TAG_NAME, 'td')
            actual_cve_number = int(columns.pop(0).text)

            if actual_cve_number > number_cve:
                ok = False
                break

            cve_id = columns.pop(0).text
            update_date = columns.pop(4).text
            Description = rows.pop(0).find_element(By.TAG_NAME, 'td').text
            got = False
            for cve in json_data:
                if cve_id == cve['CVE_ID']:
                    got = True
                    if not update_date == cve['Update Date']:
                        print("update", cve['CVE_ID'], cve['Update Date'])
                        json_data.remove(cve)
                        got = False

            if not got:
                cve_data = {'CVE_ID': '', 'CWE_ID': '', '#': '', 'Vulnerability': '', 'Publish Date': '',
                            'Update Date': '', 'Score': '', 'Gained Access Level': '', 'Access': '', 'Complexity': '',
                            'Authentication': '', 'Conf': '', 'Integ': '', 'Avail': '', 'Description': '',
                            'Products Affected': []}

                cve_data['Description'] = Description
                cve_data['CVE_ID'] = cve_id
                cve_data['Update Date'] = update_date
                for i in range(1, 13):
                    if i == 5:
                        pass
                    else:
                        cve_data[list(cve_data)[i]] = columns.pop(0).text

                driver.execute_script('window.open("' + link + '","_blank");')
                driver.switch_to.window(driver.window_handles[1])

                try:
                    tab_product_affected = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.ID, "vulnprodstable"))).find_element(By.TAG_NAME,
                                                                                                'tbody').find_elements(
                        By.TAG_NAME, 'tr')[1:]
                    for tr in tab_product_affected:
                        data_product = {'id': '', 'Product Type': '', 'Vendor': '', 'Product': '', 'Version': '',
                                        'Update': '', 'Edition': '', 'Language': ''}
                        tds = tr.find_elements(By.TAG_NAME, 'td')
                        for j in range(0, 7):
                            data_product[list(data_product)[j]] = tds.pop(0).text
                        cve_data['Products Affected'].append(data_product)
                except:
                    print("")
                driver.close()
                driver.switch_to.window(driver.window_handles[0])
                print(cve_cpt, cve_id, update_date, "add")
                json_data.append(cve_data)

            print(cve_cpt, "/", number_cve)
    with open(cve_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, ensure_ascii=False, indent=4)
    f.close()
    driver.close()


def search_cve_id(product_name, product_version):
    result = []
    with open(cve_file, encoding='utf-8') as json_file:
        cve_list = json.load(json_file)
    json_file.close()

    for cve in cve_list:
        for product in cve['Products Affected']:
            if product['Product'].lower() == product_name.lower():
                if product_version:
                    if product_version.lower() == product['Version']:
                        result.append(cve['CVE_ID'])
                        break
                else:
                    result.append(cve['CVE_ID'])
                    break
    return result


def search_cve_id(product_name):
    result = []
    with open(cve_file, encoding='utf-8') as json_file:
        cve_list = json.load(json_file)
    json_file.close()

    for cve in cve_list:
        for product in cve['Products Affected']:
            if product['Product'].lower() == product_name.lower():
                result.append(cve['CVE_ID'])
                break
    return result


def get_cve_data(cve_id):
    with open(cve_file, encoding='utf-8') as json_file:
        cve_list = json.load(json_file)
    json_file.close()
    for cve in cve_list:
        if cve['CVE_ID'] == cve_id:
            return cve
