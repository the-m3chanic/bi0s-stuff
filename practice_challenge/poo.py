import re

wanted = re.compile('= \d*')

with open("con.txt", 'r') as file:
	data = file.read()

foo = wanted.findall(data)
final = ''.join([chr(int(i.lstrip('= '))) for i in foo])
print(final)


