import logging
import argparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def run_headless_test():
    parser = argparse.ArgumentParser(description='Run headless browser test.')
    parser.add_argument('browser_type', choices=['chrome', 'firefox'], help='Browser type (chrome or firefox)')
    args = parser.parse_args()

    if args.browser_type.lower() == 'chrome':
        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})
        service = webdriver.ChromeService(log_output="chrome-driver.log")
        driver = webdriver.Chrome(options=options, service=service)
    elif args.browser_type.lower() == 'firefox':
        options = webdriver.FirefoxOptions()
        options.add_argument("--headless")
        service = webdriver.FirefoxService(log_output="firefox-driver.log", service_args=['--log', 'debug'])
        driver = webdriver.Firefox(options=options, service=service)
    else:
        logging.error("Invalid browser type. Supported types are 'chrome' and 'firefox'.")
        return

    try:
        driver.get('http://localhost:8080/')

        # Adjust the timeout to 15 minutes
        wait = WebDriverWait(driver, 900)

        # Wait until the div with id "tests_finished" is displayed
        tests_finished_element = wait.until(EC.presence_of_element_located((By.ID, "tests_finished")))

        html = driver.page_source
        result_file = f"{args.browser_type.lower()}-results.html"
        with open(result_file, "w", encoding="utf-8") as file:
            file.write(html)

        if args.browser_type.lower() == 'chrome':
            logs = driver.get_log('browser')
            # Save console logs to a file for easier debugging
            with open("chrome-console.log", "w", encoding="utf-8") as f:
                for entry in logs:
                    f.write(f"[{entry['level']}] {entry['message']}\n")
        elif args.browser_type.lower() == 'firefox':
            print("Console logs cannot be retrieved from Firefox via get_log('browser'). This feature is only supported in Chrome.")

    finally:
        driver.quit()

if __name__ == "__main__":
    run_headless_test()
