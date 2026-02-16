import json
import time
from common.config import LOG_FILE


class LogAgent:
    def __init__(self):
        self.previous_hash = "0"

    def collect_log(self):
      
        log_entry = {
            "timestamp": time.time(),
            "level": "INFO",
            "message": "User login attempt"
        }
        return log_entry

    def format_log(self, log_entry):
       
        return json.dumps(log_entry)


def main():
    agent = LogAgent()

    log = agent.collect_log()
    formatted = agent.format_log(log)

    print("Collected Log:")
    print(formatted)


if __name__ == "__main__":
    main()
