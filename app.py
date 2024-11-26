import os
# import mesop as me
# import mesop.labs as mel
import time
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

import base64
import binascii

def AWSAccount_from_AWSKeyID(AWSKeyID):
    try:
        trimmed_AWSKeyID = AWSKeyID[4:]
        x = base64.b32decode(trimmed_AWSKeyID)
        y = x[0:6]
        
        z = int.from_bytes(y, byteorder='big', signed=False)
        mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)
        
        e = (z & mask)>>7
        return (e)
    except base64.binascii.Error:
        raise ValueError("Invalid base32 encoding in AWS Key ID")
    except Exception as e:
        raise ValueError(f"Error processing AWS Key ID: {str(e)}")

# print ("account id:" + "{:012d}".format(AWSAccount_from_AWSKeyID("ASIAQNZGKIQY56JQ7WML")))

def validate_string(input_string):
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    
    # Check if the string is exactly 20 characters long
    if len(input_string) != 20:
        return False
    
    # Check if the first 4 characters are letters
    if not input_string[:4].isalpha():
        return False
    
    # Check if all characters are valid
    if not all(char in valid_chars for char in input_string):
        return False
    
    return True

def keyid_to_accountid(sText):
    try:
        logging.info("Starting keyid_to_accountid function")
        sText = sText.strip()
        result = validate_string(sText)
        print(f"Is '{sText}' valid? {result}")
        
        if result:
            account_id = AWSAccount_from_AWSKeyID(sText)
            return "{:012d}".format(account_id)
        else: 
            return "Invalid Input :\\"
            
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        return f"An unexpected error occurred: {str(e)}"

if __name__ == "__main__":
    logging.info("Application started")
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert AWS Key ID to Account ID')
    parser.add_argument('--awskeyid', type=str, required=True, help='AWS Key ID to convert')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Process the key ID and print result
    result = keyid_to_accountid(args.awskeyid)
    print(f"Access Key ID To Account ID #: {args.awskeyid}")
    print(f"AWS Account ID: {result}")