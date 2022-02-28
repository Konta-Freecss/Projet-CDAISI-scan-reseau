from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
import json

ser = Service(r'C:\geckodriver.exe')
driver = webdriver.Firefox(service=ser)


driver.get("https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
number_cve = int(driver.find_element(By.XPATH, '//*[@id="pagingb"]/b').text)
json_data = []

ok = True
page_num = 0
cve_cpt = 0
while ok:
    page_num = page_num + 1
    driver.get("https://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page="+str(page_num)+"&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=9&cvssscoremax=10&year=0&month=0&cweid=0&order=1&trc=19275&sha=c560d509f935c26128bfb13d2f2dadfcea62215b")
    rows = driver.find_element(By.ID, "vulnslisttable").find_element(By.TAG_NAME,'tbody').find_elements(By.TAG_NAME,'tr')[1:]
    for i in range(0,len(rows),2):
        cve_cpt = cve_cpt + 1
        columns = rows.pop(0).find_elements(By.TAG_NAME, 'td')
        actual_cve_number = int(columns.pop(0).text)
        if actual_cve_number >= number_cve:
            ok = False
            break

        cve_data = {'CVE_ID':'','CWE_ID':'','#':'','Vulnerability':'','Publish Date':'','Update Date':'','Score':'','Gained Access Level':'','Access':'','Complexity':'','Authentication':'','Conf':'','Integ':'','Avail':'','Description':''}

        cve_data['Description'] = rows.pop(0).find_element(By.TAG_NAME,'td').text
        for i in range(0, 13):
            cve_data[list(cve_data)[i]] = columns.pop(0).text

        print(cve_cpt,"/",number_cve)
        json_data.append(cve_data)


with open('data.json', 'w', encoding='utf-8') as f:
    json.dump(json_data, f, ensure_ascii=False, indent=4)
    
driver.close()
