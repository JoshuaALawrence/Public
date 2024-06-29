import imaplib
import email
import re
import csv
import os
from email.header import decode_header
from email.utils import parseaddr

# This script will look through all emails and any containing emojis will be deleted, most emails containing emojis are spam/scam.

# Your Gmail credentials and IMAP server details
username = 'your_email@gmail.com'
app_password = 'your_app_password'  # Your app password
imap_url = 'imap.gmail.com'

# Define a regex pattern for emojis globally
emoji_pattern = re.compile("[" 
    u"\U0001F600-\U0001F64F"  # emoticons
    u"\U0001F300-\U0001F5FF"  # symbols & pictographs
    u"\U0001F680-\U0001F6FF"  # transport & map symbols
    u"\U0001F700-\U0001F77F"  # alchemical symbols
    u"\U0001F780-\U0001F7FF"  # Geometric Shapes Extended
    u"\U0001F800-\U0001F8FF"  # Supplemental Arrows-C
    u"\U0001F900-\U0001F9FF"  # Supplemental Symbols and Pictographs
    u"\U0001FA00-\U0001FA6F"  # Chess Symbols
    u"\U0001FA70-\U0001FAFF"  # Symbols and Pictographs Extended-A
    u"\U00002702-\U000027B0"  # Dingbats
    u"\U000024C2-\U0001F251"
    "]+", flags=re.UNICODE)

# Function to strip emojis from text
def strip_emojis(text):
    return emoji_pattern.sub(r'', text)

# Connect to the Gmail IMAP server
mail = imaplib.IMAP4_SSL(imap_url)
mail.login(username, app_password)

# Process emails, moving and deleting as necessary
def process_emails(folder):
    mail.select(f'"{folder}"', readonly=False)
    result, data = mail.search(None, "ALL")
    if result == "OK":
        for num in data[0].split():
            typ, msg_data = mail.fetch(num, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    msg_subject, encoding = decode_header(msg.get('Subject'))[0]
                    subject = msg_subject.decode(encoding if encoding else 'utf-8')
                    sender = parseaddr(msg.get('From'))[1]
                    if emoji_pattern.search(subject):
                        body = msg.get_payload(decode=True)
                        body_text = body.decode() if body else ""
                        if folder == '[Gmail]/Trash':
                            mail.store(num, '+FLAGS', '\\Deleted')
                        else:
                            mail.store(num, '+X-GM-LABELS', '\\Trash')
        mail.expunge()

folders = ['inbox', '[Gmail]/Spam']
for folder in folders:
    process_emails(folder)

# After processing the inbox and spam, process the Trash folder
process_emails('[Gmail]/Trash')

mail.close()
mail.logout()
