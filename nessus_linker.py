#!/usr/bin/env python3
import argparse
import os
import pandas as pd
import pyzipper
import shutil
import time
import sys
from pathlib import Path
from sys import platform as _platform
from xlutils.copy import copy
import zipfile
import zlib

parser = argparse.ArgumentParser(
	usage="%(prog)s <optional arguments>",
	description="Current options are to zip file and password protect zip file (not available on Windows)."
)
parser.add_argument('-z', '--zip', action='store_true', help='Zips final workbooks', required=False)
parser.add_argument('-p', '--password_protect', action='store_true', help='Password protects zipfile', required=False)
args = parser.parse_args()

HOME = Path.home()

def banner():
	print("########################################################################################")
	print("#                     Nessus CSV Report Beautifier and Zip                             #")
	print("#                                by Will Harmon                                        #")
	print("#                                                                                      #")
	print("# This script converts Nessus scan results from CSV to XLSX, and adds a hyperlink to   #")
	print("# the plugin-id values so admins can click for additional details from Tenable web-    #")
	print("# site directly from spreadsheet. Also adds color to the header and provides optional  #")
	print("# capability to add converted XLSX files to a password protected ZIP.                  #")
	print("########################################################################################")
	print("\n")


# Sets the password to use with password protected zip file
def password_set():
	print("Please enter a password for your zip file.")
	check = False
	# While loop to continue asking for passwords if they don't match
	while check == False:
		password = input("Password:\n")
		password2 = input("Re-enter password:\n")
		check = password_check(password, password2)
		if check == False:
			print("[-] Passwords don't match; please try again.\n")
	# Convert password into bytes for pyzipper
	b_password = bytes(password, 'utf-8')
	return b_password

# Compares two passwords and returns boolean 
def password_check(password, password2):
	if password == password2:
		return True
	else:
		return False

# Zips and password protects the modified XLSX files.	
def zipup(workbooks, multi):
	modified_results = f'{HOME}/ScanResults/ModifiedResults'
	workbooks = workbooks
	# Branch processing on whether password protect argument was passed
	if args.password_protect:
		b_password = password_set()
		# Multi booleans checks for whether multiple xlsx files will be added to zip or just a single xlsx file
		if multi == False:
			# Enumeration of workbooks list occurs before pyzipper instantiation since there is only one xlsx file to add
			for workbook in workbooks:
				filename = workbook.split("/")[-1]
				print(f'[+] Attempting to zip {filename}\n')
				wb2 = (filename.replace(".xlsx",""))
				with pyzipper.AESZipFile(f'{modified_results}/{wb2}.zip', 'w', encryption=pyzipper.WZ_AES) as zf:
					zf.setpassword(b_password)
					zf.write(f'{modified_results}/{filename}', arcname=filename)
			print(f'{wb2}.zip created in {modified_results}')
		if multi == True:
			multi_zip_name = input("Enter a name for the multi-file zip.\n")
			print("")
			with pyzipper.AESZipFile(f'{modified_results}/{multi_zip_name}.zip', 'w', encryption=pyzipper.WZ_AES) as zf:
					zf.setpassword(b_password)
					# Enumeration of workbooks list happens after pyzipper instantiation and password set so these don't occur 
					# for each new workbook iteration
					for workbook in workbooks:
						filename = workbook.split("/")[-1]
						print(f'[+] Adding {filename} to zip.')
						wb2 = (filename.replace(".xlsx",""))
						zf.write(f'{modified_results}/{filename}', arcname=filename)
					zf.close()
					print(f'\n[+] {multi_zip_name}.zip created in {modified_results}')
	
	# This section pertains to zip only; no password. Since no password, zipfile is used instead of pyzipper
	else:
		if multi == False:
			for workbook in workbooks:
				filename = workbook.split("/")[-1]
				print(f'[+] Attempting to zip {filename}\n')
				wb2 = (filename.replace(".xlsx",""))
				zf = zipfile.ZipFile(f'{modified_results}/{wb2}.zip', mode='w')

				try:
					compression = zipfile.zipfile.ZIP_DEFLATED
				except:
					compression = zipfile.ZIP_STORED

				modes = { zipfile.ZIP_DEFLATED: 'deflated',
						zipfile.ZIP_STORED: 'stored',
				}
				try:
					zf.write(f'{modified_results}/{filename}', arcname = filename, compress_type=compression)
					print(f'{wb2}.zip created in {modified_results}')
				finally:
					zf.close()
		if multi == True:
			multi_zip_name = input("Enter name for multi-file zip.\n")
			zf = zipfile.ZipFile(f'{modified_results}/{multi_zip_name}.zip', mode='w')
			try:
				compression = zipfile.zipfile.ZIP_DEFLATED
			except:
				compression = zipfile.ZIP_STORED
			modes = { zipfile.ZIP_DEFLATED: 'deflated',
					zipfile.ZIP_STORED: 'stored',
			}
			try:
				print("\n[+] Adding files to zip...")
				for workbook in workbooks:
					filename = workbook.split("/")[-1]
					print(f'[+] Adding {filename} to zip.')
					wb2 = (filename.replace(".xlsx",""))
					zf.write(f'{modified_results}/{filename}', arcname = filename, compress_type=compression)
				print(f'\n[+] {wb2}.zip created in {modified_results}')
			finally:
				zf.close()
# Returns hyperlink to be added to the plug-in values in the XLSX file
def make_hyperlink(value):
	tenable_url = 'https://tenable.com/plugins/nessus/'
	return f'=HYPERLINK("{tenable_url}{value}","{value}")'

# pre_main ensures the necessary directory structure is in place for processing. If not
# already present, will add the following directories: ScanResults, ModifiedResults, and OldResults 
# in users home directory.
def pre_main():
	print("[+] Checking for ScanResults directory")
	if not os.path.exists(f'{HOME}/ScanResults'):
		print("[-] ScanResults directory not found")
		print("[+] Creating a ScanResults directory in your home directory.")
		os.makedirs(f'{HOME}/ScanResults')
		print(f'[+] ScanResults directory created in, {HOME}.')
	if not os.path.exists(f'{HOME}/ScanResults/ModifiedResults'):
		print("[-] ModifiedResults directory not found.")	
		os.makedirs(f'{HOME}/ScanResults/ModifiedResults')
		print("[+] ModifiedResults directory created.")
	if not os.path.exists(f'{HOME}/ScanResults/OldResults'):
		print("[-] OldResults directory not found.")	
		os.makedirs(f'{HOME}/ScanResults/OldResults')
		print("[+] OldResults directory created.")
	else:
		print("[+] ScanResults directory found!\n")
	print(f'Before continuing, place one or more Nessus csv scan results in, {HOME}/ScanResults.')
	
# Function to search for CSV files at the determined start location, and add the path from 
# discovered CSV files to the workbooks list
def file_finder(location):
	workbooks = []
	print("[+] Looking for csv files...")
	working_directory = Path(location)
	for file in working_directory.iterdir():
		if str(file).endswith('.csv'):
			workbooks.append(file)
	return workbooks

def main():
	original_location = f'{HOME}/ScanResults'
	final_location = f'{HOME}/ScanResults/ModifiedResults'
	archive_location = f'{HOME}/ScanResults/OldResults'	
	conversion_count = 0
	modified_results = []

	# workbooks list is assigned the output list from the file_finder function
	workbooks = file_finder(original_location)
	# If workbooks is empty, function will end; otherwise continues for processing.
	if len(workbooks) > 0:
		print(f'[+] {len(workbooks)} csv file(s) found.\n')
		for num_of_files, file in enumerate(workbooks):	
			filename = str(file).split("/")[-1]
			print(f'[+] Processing {filename}')
			# Open csv file in pandas
			df = pd.read_csv(file)
			# Add the plugin ID link into the Plugin ID column values by way of the make_hyperlink function
			df['Plugin ID'] = df['Plugin ID'].apply(lambda x: make_hyperlink(x))
			# Stylize the XLSX file
			# Create pandas excel writer with xlswriter 
			writer = pd.ExcelWriter(f'{final_location}/{filename.split(".")[0]}.xlsx', engine = 'xlsxwriter')
			# Convert df to xlswriter excel object for converting to xlsx
			df.to_excel(writer, sheet_name = 'Nessus Results', index = False)
			# Instantiate the xlswriter workbook and worksheet objects
			workbook = writer.book
			worksheet = writer.sheets['Nessus Results']
			# Create custom formatting for xlsx header row
			header_format = workbook.add_format({
				'bold': True,
				'text_wrap': False,
				'valign': 'top',
				'font_color': 'black',
				'fg_color': '#6495ed',
				'border': 1
			})
			# Create custom style for Plugin ID column values and apply it
			cell_format = workbook.add_format({
				'font_color': 'blue'
			})
			worksheet.set_column('A:A', None, cell_format)
			# Write custom column headers with header_format values from above.
			for col_num, value in enumerate(df.columns.values):
				worksheet.write(0, col_num, value, header_format)
			# Close writer and save xlsx to directory
			writer.save()
			modified_results.append(f'{final_location}/{filename.split(".")[0]}.xlsx')
			print('[+] Processing complete.')
			# Increment counter for each successful conversion
			conversion_count += 1
			print(f'[+] Moving {filename} to {archive_location}.\n')
			# Move original csv file into OldResults directory
			shutil.move(file, f'{archive_location}/{filename}')
		print(f'[+] Complete; {conversion_count} csv file(s) converted into xlsx and located at {final_location}.')
	else:
		print("[-] No csv files were found; please copy Nessus csv results into ScanResults directory and try again.")
		sys.exit(0)
		
	return modified_results
	
if __name__ == '__main__':
	banner()
	pre_main()
	ans = input("Ready to continue? [y or n]\n")
	if ans.lower() == 'y':
		print("")
		if args.zip == True:
			workbooks = main()
			print("Starting zip and password process.\n")
			if len(workbooks) > 0:
				if len(workbooks) > 1:
					multi = True
				else:
					multi = False
				zipup(workbooks, multi)
				print("\nFinished - goodbye!\n")

		else:
			main()
			print("\nFinished - goodbye!\n")
	else:
		print("[+] Goodbye!")
		sys.exit(0)



