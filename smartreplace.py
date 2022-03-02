import csv, sys

readfile = sys.argv[1]
# readfile = "SSH_KEY.csv"

writefile = sys.argv[2]
# writefile = "something"

param_rows = []

# reads csv file
with open(readfile, 'r') as file_contents:
	contents = csv.reader(file_contents, delimiter=',', quotechar='|')
	for row in contents:
		print(row[0] + " " + row[1])
		param_rows.append([row[0], row[1]])

param_rows = param_rows[1:] # clears header

# reads file content
with open(writefile, 'r') as file_content:
	content = file_content.read().splitlines()

for item in param_rows:
	flag = False	# checks if content in file
	# print(item[0])
	for index in range(0, len(content)): # check
		if (item[0] in content[index]) and (content[index][0] != "#"):
			content[index] = item[0] + " " + item[1] # replaces
			flag = True
	if flag is False: # adds
		content.append(item[0] + " " + item[1])

# print(content)   

with open(writefile, 'w') as file:
	for line in content:
		file.write(line + '\n')